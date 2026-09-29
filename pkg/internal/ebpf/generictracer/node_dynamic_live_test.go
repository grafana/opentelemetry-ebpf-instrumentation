// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && node_live

package generictracer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestNodeDynamicSpansLive(t *testing.T) {
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	agentDir := os.Getenv("OBI_NODE_AGENT_DIR")
	require.NotEmpty(t, agentDir)
	directory := t.TempDir()
	source := filepath.Join(directory, "target.cjs")
	require.NoError(t, os.WriteFile(source, []byte(nodeDynamicTargetSource), 0o600))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), ReadHeaderTimeout: time.Second}
	go func() { _ = backend.Serve(listener) }()
	t.Cleanup(func() { _ = backend.Close() })
	cmd := exec.Command("node", source, listener.Addr().String(), agentDir)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(output)
	require.True(t, scanner.Scan())
	port := scanner.Text()
	pid := app.PID(cmd.Process.Pid)
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.DynamicInstrumentation.Enabled = true
	cfg.EBPF.TrackRequestHeaders = true
	filters := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	tracer := New(filters, &cfg, imetrics.NoopReporter{})
	events := ebpfcommon.NewEBPFEventContext()
	events.CommonPIDsFilter = filters
	pt := obiebpf.NewProcessTracer(obiebpf.Generic, []obiebpf.Tracer{tracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, pt.Init(events, &cfg))
	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	executable, err := os.Readlink(exePath)
	require.NoError(t, err)
	info, err := os.Stat(exePath)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	fi := discexec.New(discexec.Init{
		Pid: pid, Ns: ns, CmdExePath: executable, ProExeLinkPath: exePath,
		Dev: uint64(stat.Dev), Ino: stat.Ino, Service: svc.Attrs{UID: svc.UID{Name: "node-live"}, SDKLanguage: svc.InstrumentableNodejs},
	})
	pt.AllowPID(pid, ns, fi)
	binary, err := link.OpenExecutable(exePath)
	require.NoError(t, err)
	probe, err := binary.UprobeMulti([]string{"uv_fs_access"}, tracer.bpfObjects.ObiUvFsAccess, &link.UprobeMultiOptions{PID: uint32(pid)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = probe.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	registry := nodejs.NewDynamicRegistry(ctx, cfg.DynamicInstrumentation, events)
	target := registry.Target(pid, pt)
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	spans := queue.Subscribe(msg.SubscriberName("node-live"))
	done := make(chan struct{})
	go func() { defer close(done); pt.Run(ctx, events, queue) }()
	t.Cleanup(func() { cancel(); <-done; queue.Close() })
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "*target.cjs:exports.*")
		return err == nil && len(names) == 2
	}, 15*time.Second, 100*time.Millisecond)
	var probes []io.Closer
	for i, name := range []string{"outer", "inner"} {
		spec := config.CustomSpanSpec{Name: name, On: config.CustomSpanTarget{FunctionSpan: source + ":exports." + name}}
		attached, err := target.AttachLiveSpan(pid, ns, &spec, uint64(i+1), name, 1)
		require.NoError(t, err)
		probes = append(probes, attached)
	}
	requestHTTP, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://127.0.0.1:"+port+"/outer", nil)
	require.NoError(t, err)
	requestHTTP.Header.Set("traceparent", "00-12345678901234567890123456789012-1234567890123456-00")
	response, err := http.DefaultClient.Do(requestHTTP)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, "43", string(body))
	received := map[string]request.Span{}
	deadline := time.After(10 * time.Second)
	for len(received) < 4 {
		select {
		case batch := <-spans:
			for _, span := range batch {
				switch span.Type {
				case request.EventTypeCustomSpan:
					received[span.Method] = span
				case request.EventTypeHTTPClient:
					received["client"] = span
				case request.EventTypeHTTP:
					received["server"] = span
				}
			}
		case <-deadline:
			t.Fatalf("missing Node spans: %+v", received)
		}
	}
	outer, inner, server, client := received["outer"], received["inner"], received["server"], received["client"]
	require.Equal(t, server.TraceID, outer.TraceID)
	require.Zero(t, outer.TraceFlags, "custom spans must preserve an unsampled parent")
	require.Equal(t, outer.TraceFlags, inner.TraceFlags)
	require.Equal(t, server.SpanID, outer.ParentSpanID)
	require.Equal(t, outer.TraceID, inner.TraceID)
	require.Equal(t, outer.SpanID, inner.ParentSpanID)
	require.Equal(t, inner.TraceID, client.TraceID)
	require.Equal(t, inner.SpanID, client.ParentSpanID)
	require.Equal(t, "42", outer.CustomSpan.Attrs["arg0"])
	require.Equal(t, "hello", outer.CustomSpan.Attrs["arg1"])
	require.Equal(t, "43", outer.CustomSpan.Attrs["return0"])
	for i, attached := range probes {
		count, err := attached.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		require.Equal(t, uint64(1), count)
		require.NoError(t, attached.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+1), &value), ebpf.ErrKeyNotExist)
	}
	var key BpfNodeDynamicKey
	var call BpfNodeDynamicContext
	require.False(t, tracer.bpfObjects.NodeDynamicCalls.Iterate().Next(&key, &call))
	response, err = http.Get("http://127.0.0.1:" + port + "/after-delete")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case batch := <-spans:
			for _, span := range batch {
				require.NotEqual(t, request.EventTypeCustomSpan, span.Type)
			}
		case <-timer.C:
			return
		}
	}
}

const nodeDynamicTargetSource = `
const fs = require('fs');
const http = require('http');
const path = require('path');
let extractor = fs.readFileSync(path.join(process.argv[3], 'fdextractor.js'), 'utf8');
extractor = extractor.replace('false; /*OBI_TRACES_ENABLED*/', 'true; /*OBI_TRACES_ENABLED*/')
 .replace('false; /*OBI_CTX_HOOK_ENABLED*/', 'true; /*OBI_CTX_HOOK_ENABLED*/');
eval(extractor);
require(path.join(process.argv[3], 'dynamic.js'));
exports.outer = async function outer(x, text) { return exports.inner(x); };
exports.inner = async function inner(x) {
 await new Promise((resolve, reject) => {
  http.get('http://' + process.argv[2] + '/nested', res => {
   res.resume(); res.on('end', resolve);
  }).on('error', reject);
 });
 return x + 1;
};
http.createServer((req, res) => {
 exports.outer(42, 'hello').then(value => res.end(String(value)));
}).listen(0, '127.0.0.1', function () { console.log(this.address().port); });
`
