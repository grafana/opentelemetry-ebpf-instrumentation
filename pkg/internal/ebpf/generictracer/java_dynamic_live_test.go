// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && jvm_live

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
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestJavaDynamicSpansLive(t *testing.T) {
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	jar := os.Getenv("OBI_JAVA_AGENT_JAR")
	require.NotEmpty(t, jar, "set OBI_JAVA_AGENT_JAR to the built agent")
	directory := t.TempDir()
	source := filepath.Join(directory, "DynamicTarget.java")
	require.NoError(t, os.WriteFile(source, []byte(javaDynamicTargetSource), 0o600))
	out, err := exec.Command("javac", source).CombinedOutput()
	require.NoError(t, err, string(out))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serverHTTP := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), ReadHeaderTimeout: time.Second}
	go func() { _ = serverHTTP.Serve(listener) }()
	t.Cleanup(func() { _ = serverHTTP.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	cmd := exec.Command("java", "-javaagent:"+jar+"=dynamicInstrumentation=true", "-cp", directory, "DynamicTarget", port)
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(output)
	require.True(t, scanner.Scan())
	tid, err := strconv.Atoi(scanner.Text())
	require.NoError(t, err)
	pid := app.PID(cmd.Process.Pid)

	cfg := obi.DefaultConfig
	cfg.DynamicInstrumentation.Enabled = true
	cfg.EBPF.BpfDebug = true
	filters := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	tracer := New(filters, &cfg, imetrics.NoopReporter{})
	events := ebpfcommon.NewEBPFEventContext()
	events.CommonPIDsFilter = filters
	pt := obiebpf.NewProcessTracer(obiebpf.Generic, []obiebpf.Tracer{tracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, pt.Init(events, &cfg))
	fi := javaProcessFileInfo(t, pid)
	pt.AllowPID(pid, fi.Ns(), fi)
	ctx, cancel := context.WithCancel(context.Background())
	registry := javaagent.NewDynamicRegistry(ctx, cfg.DynamicInstrumentation, events)
	target := registry.Target(pid, pt)
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	spans := queue.Subscribe(msg.SubscriberName("dynamic-java-test"))
	done := make(chan struct{})
	go func() { defer close(done); pt.Run(ctx, events, queue) }()
	t.Cleanup(func() { cancel(); <-done; queue.Close() })
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "DynamicTarget.*")
		return err == nil && len(names) >= 3
	}, 15*time.Second, 100*time.Millisecond)

	var traceID trace.TraceID
	var serverID trace.SpanID
	traceID[0] = 23
	serverID[0] = 42
	key := BpfTraceKeyT{P_key: BpfPidKeyT{Tid: uint32(tid), Pid: uint32(pid), Ns: fi.Ns()}}
	server := BpfTpInfoPidT{Tp: BpfTpInfoT{TraceId: traceID, SpanId: serverID, Flags: 1, Ts: uint64(timing.MonoTimeNow())}, Pid: uint32(pid), Valid: 1}
	require.NoError(t, tracer.bpfObjects.ServerTraces.Update(&key, &server, ebpf.UpdateAny))
	probes := make([]io.Closer, 0, 2)
	for i, method := range []string{"outer", "inner"} {
		spec := config.CustomSpanSpec{Name: method, On: config.CustomSpanTarget{FunctionSpan: "DynamicTarget." + method}}
		probe, err := target.AttachLiveSpan(pid, fi.Ns(), &spec, uint64(i+1), method, 1)
		require.NoError(t, err)
		probes = append(probes, probe)
	}
	_, err = io.WriteString(input, "CALL\n")
	require.NoError(t, err)
	received := map[string]request.Span{}
	var client request.Span
	deadline := time.After(10 * time.Second)
	for len(received) < 2 || !client.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan {
					received[span.Method] = span
				}
				if span.Type == request.EventTypeHTTPClient {
					client = span
				}
			}
		case <-deadline:
			t.Fatalf("missing Java spans: %+v", received)
		}
	}
	outer, inner := received["outer"], received["inner"]
	require.Equal(t, traceID, outer.TraceID)
	require.Equal(t, serverID, outer.ParentSpanID)
	require.Equal(t, outer.TraceID, inner.TraceID)
	require.Equal(t, outer.SpanID, inner.ParentSpanID)
	require.Equal(t, inner.TraceID, client.TraceID)
	require.Equal(t, inner.SpanID, client.ParentSpanID, "automatic client must inherit the innermost Java method")
	require.Equal(t, "42", outer.CustomSpan.Attrs["arg0"])
	require.Equal(t, "hello", outer.CustomSpan.Attrs["arg1"])
	require.Equal(t, "43", outer.CustomSpan.Attrs["return0"])
	for i, probe := range probes {
		count, err := probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.NoError(t, err)
		require.Equal(t, uint64(1), count)
		require.NoError(t, probe.Close())
		var value uint64
		require.ErrorIs(t, tracer.bpfObjects.ObiDynamicInvocations.Lookup(uint64(i+1), &value), ebpf.ErrKeyNotExist)
	}
	_, err = io.WriteString(input, "CALL\n")
	require.NoError(t, err)
	require.True(t, scanner.Scan())
	require.Equal(t, "43", scanner.Text())
	require.True(t, scanner.Scan())
	require.Equal(t, "43", scanner.Text())
	select {
	case batch := <-spans:
		for _, span := range batch {
			require.NotEqual(t, request.EventTypeCustomSpan, span.Type, fmt.Sprintf("custom span after deletion: %+v", span))
		}
	case <-time.After(200 * time.Millisecond):
	}
	var current BpfJavaDynamicContext
	require.ErrorIs(t, tracer.bpfObjects.JavaDynamicSpans.Lookup(&key, &current), ebpf.ErrKeyNotExist)
	var restored BpfTpInfoPidT
	require.NoError(t, tracer.bpfObjects.ServerTraces.Lookup(&key, &restored))
	require.Equal(t, server, restored, "custom spans must preserve automatic server state")
}

const javaDynamicTargetSource = `
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
public class DynamicTarget {
 private static int port;
 public static int outer(int x, String text) throws Exception { return inner(x); }
 public static int inner(int x) throws Exception {
  try (Socket socket = new Socket("127.0.0.1", port)) {
   socket.getOutputStream().write("GET /nested HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
   while (socket.getInputStream().read() != -1) {}
  }
  return x + 1;
 }
 public static void main(String[] args) throws Exception {
  port = Integer.parseInt(args[0]);
  Class<?> nativeLib = Class.forName("io.opentelemetry.obi.java.Agent$NativeLib", true, null);
  System.out.println(nativeLib.getMethod("gettid").invoke(null));
  BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
  while (input.readLine() != null) System.out.println(outer(42, "hello"));
 }
}
`
