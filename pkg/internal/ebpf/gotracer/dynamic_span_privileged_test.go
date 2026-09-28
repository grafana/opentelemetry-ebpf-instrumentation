// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestDynamicSpansSDKParentAndDetach(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "requires BPF privileges")
	require.NoError(t, rlimit.RemoveMemlock())
	binary := os.Getenv("OBI_DYNAMIC_TEST_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "dynamicspans")
		output, err := exec.Command("go", "build", "-o", binary, "testdata/dynamicspans/main.go").CombinedOutput()
		require.NoError(t, err, string(output))
	}
	command := exec.CommandContext(t.Context(), binary)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	lines := collectClientLines(t, "dynamic target", stdout)
	ready := waitForClientLine(t, lines, "READY=", time.Second*10)
	pid := app.PID(command.Process.Pid)
	cfg := obi.DefaultConfig
	cfg.DynamicInstrumentation.Enabled = true
	cfg.EBPF.PopulateTraceContext = true
	cfg.EBPF.BufferSizes.HTTP = 65536
	cfg.EBPF.PayloadExtraction.HTTP.Enrichment.Enabled = true
	cfg.EBPF.BatchLength = 1
	cfg.EBPF.BatchTimeout = 10 * time.Millisecond
	pids := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	goTracer := New(pids, &cfg, imetrics.NoopReporter{})
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = pids
	tracer := ebpftracer.NewProcessTracer(ebpftracer.Go, []ebpftracer.Tracer{goTracer}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, tracer.Init(eventContext, &cfg))
	info := goProcessFileInfo(t, pid)
	offsets, err := goexec.InspectOffsets(info, goFunctionNames(&cfg))
	require.NoError(t, err)
	ebpftracer.AddSDKContextOffsets(info.ELF(), offsets)
	t.Logf("SDK context offset: %v; SDK itab: %#x; span ID offset: %v", offsets.Field[goexec.SDKRecordingSpanContextPos], offsets.ITypes["*go.opentelemetry.io/otel/sdk/trace.recordingSpan,go.opentelemetry.io/otel/trace.Span"], offsets.Field[goexec.SpanContextSpanIDPos])
	require.NotZero(t, offsets.ITypes["*go.opentelemetry.io/otel/sdk/trace.recordingSpan,go.opentelemetry.io/otel/trace.Span"])
	require.NotEmpty(t, offsets.Funcs["go.opentelemetry.io/otel/sdk/trace.(*tracer).Start"])
	tracer.AllowPID(pid, info.Ns(), info)
	executable, err := link.OpenExecutable(info.ProExeLinkPath())
	require.NoError(t, err)
	require.NoError(t, tracer.NewExecutable(executable, &ebpftracer.Instrumentable{Type: svc.InstrumentableGolang, FileInfo: info, Offsets: offsets}))
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(64))
	received := spans.Subscribe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); tracer.Run(ctx, eventContext, spans) }()
	t.Cleanup(func() { cancel(); <-done; spans.Close() })
	var probes []io.Closer
	for index, name := range []string{"outer", "inner", "outerAsync", "outerDetached", "echo", "echoAsync"} {
		probe, err := tracer.AttachLiveSpan(pid, info.Ns(), &config.CustomSpanSpec{Name: name, On: config.CustomSpanTarget{FunctionSpan: "main." + name}}, uint64(index+1), name, 1)
		require.NoError(t, err)
		probes = append(probes, probe)
		t.Cleanup(func() { _ = probe.Close() })
	}
	for _, test := range []struct {
		command string
		outer   string
		http    bool
	}{
		{command: "CALL", outer: "outer"},
		{command: "ASYNC", outer: "outerAsync"},
		{command: "DETACHED", outer: "outerDetached"},
		{command: "HTTP", outer: "outer", http: true},
		{command: "HTTP_ASYNC", outer: "outerAsync", http: true},
		{command: "HTTP_DETACHED", outer: "outerDetached", http: true},
	} {
		t.Run(test.command, func(t *testing.T) {
			_, err = io.WriteString(stdin, test.command+"\n")
			require.NoError(t, err)
			prefix, expected := "RESULT=", 2
			if test.http {
				prefix, expected = "HTTP_RESULT=", 3
			}
			result := strings.Fields(strings.TrimPrefix(waitForClientLine(t, lines, prefix, 10*time.Second), prefix))
			found := map[string]request.Span{}
			timeout := time.After(10 * time.Second)
			for len(found) < expected {
				select {
				case batch := <-received:
					for _, span := range batch {
						if span.Type == request.EventTypeCustomSpan {
							found[span.Method] = span
						}
						if test.http && span.Type == request.EventTypeHTTP {
							found["server"] = span
						}
					}
				case <-timeout:
					t.Fatalf("expected %d spans, got %v", expected, found)
				}
			}
			outer, inner := found[test.outer], found["inner"]
			if test.http {
				require.Equal(t, found["server"].SpanID, outer.ParentSpanID)
				require.Equal(t, found["server"].TraceID, outer.TraceID)
			} else {
				require.Equal(t, result[0], outer.TraceID.String())
				require.Equal(t, result[1], outer.ParentSpanID.String())
			}
			require.Equal(t, outer.SpanID, inner.ParentSpanID)
			require.Equal(t, outer.TraceID, inner.TraceID)
			if test.outer == "outerDetached" {
				require.Less(t, outer.End, inner.Start)
			}
			require.Less(t, inner.Start, inner.End)
			require.Equal(t, "hello", inner.CustomSpan.Attrs["arg0"])
			require.Equal(t, "7", inner.CustomSpan.Attrs["arg1"])
			require.Equal(t, "hello!", inner.CustomSpan.Attrs["return0"])
			require.Equal(t, "8", inner.CustomSpan.Attrs["return1"])
		})
	}
	testBinary, err := os.Executable()
	require.NoError(t, err)
	other := exec.CommandContext(t.Context(), testBinary, "-test.run=^TestDynamicGenericProcessHelper$")
	other.Env = append(os.Environ(), "OBI_DYNAMIC_GENERIC_HELPER=1")
	otherOut, err := other.StdoutPipe()
	require.NoError(t, err)
	_, err = other.StdinPipe()
	require.NoError(t, err)
	other.Stderr = os.Stderr
	require.NoError(t, other.Start())
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	otherLines := collectClientLines(t, "generic target", otherOut)
	otherURL := strings.TrimPrefix(waitForClientLine(t, otherLines, "READY=", 10*time.Second), "READY=")
	otherPID := app.PID(other.Process.Pid)
	otherInfo := goProcessFileInfo(t, otherPID)
	generic := generictracer.New(pids, &cfg, imetrics.NoopReporter{})
	genericTracer := ebpftracer.NewProcessTracer(ebpftracer.Generic, []ebpftracer.Tracer{generic}, &cfg, imetrics.NoopReporter{})
	require.NoError(t, genericTracer.Init(eventContext, &cfg))
	genericTracer.AllowPID(otherPID, otherInfo.Ns(), otherInfo)
	otherExe, err := link.OpenExecutable(otherInfo.ProExeLinkPath())
	require.NoError(t, err)
	require.NoError(t, genericTracer.NewExecutable(otherExe, &ebpftracer.Instrumentable{Type: svc.InstrumentableGeneric, FileInfo: otherInfo}))
	genericCtx, genericCancel := context.WithCancel(t.Context())
	genericDone := make(chan struct{})
	go func() { defer close(genericDone); genericTracer.Run(genericCtx, eventContext, spans) }()
	t.Cleanup(func() { genericCancel(); <-genericDone })
	require.True(t, pids.ValidPID(otherPID, otherInfo.Ns(), ebpfcommon.PIDTypeKProbes))
	require.False(t, pids.ValidPID(pid, info.Ns(), ebpfcommon.PIDTypeKProbes))
	t.Run("GENERIC_HTTP", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, otherURL+"/generic", nil)
		require.NoError(t, err)
		response, err := client.Do(req)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		timeout := time.After(10 * time.Second)
		for {
			select {
			case batch := <-received:
				for _, span := range batch {
					if span.Type == request.EventTypeHTTP && span.Path == "/generic" {
						require.Equal(t, otherPID, span.Pid.UserPID)
						return
					}
				}
			case <-timeout:
				t.Fatal("generic tracer did not emit the other process's HTTP span")
			}
		}
	})
	t.Run("HTTP_ECHO", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, strings.TrimPrefix(ready, "READY=")+"/echo", nil)
		require.NoError(t, err)
		response, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, response.Body.Close())
		found := map[string]request.Span{}
		timeout := time.After(10 * time.Second)
		for len(found) < 5 {
			select {
			case batch := <-received:
				for _, span := range batch {
					switch {
					case span.Type == request.EventTypeCustomSpan:
						found[span.Method] = span
					case span.Type == request.EventTypeHTTP && span.Path == "/echo":
						found["server"] = span
					case span.Type == request.EventTypeHTTP && span.Path == "/echoBack":
						found["downstream"] = span
					case span.Type == request.EventTypeHTTPClient && span.Path == "/echoBack":
						found["client"] = span
					}
				}
			case <-timeout:
				t.Fatalf("expected the complete HTTP echo trace, got %v", found)
			}
		}
		for name, span := range found {
			t.Logf("%s: trace=%s span=%s parent=%s ports=%d->%d", name, span.TraceID, span.SpanID, span.ParentSpanID, span.PeerPort, span.HostPort)
		}
		require.False(t, found["server"].ParentSpanID.IsValid(), "the external request has no incoming trace context")
		require.Equal(t, found["server"].TraceID, found["echoAsync"].TraceID)
		require.Equal(t, found["server"].SpanID, found["echoAsync"].ParentSpanID)
		require.Equal(t, found["echoAsync"].SpanID, found["echo"].ParentSpanID)
		require.Equal(t, found["echo"].TraceID, found["client"].TraceID)
		require.Equal(t, found["server"].SpanID, found["client"].ParentSpanID, "HTTP client must retain its active server parent")
		require.Equal(t, found["client"].TraceID, found["downstream"].TraceID)
		require.Equal(t, found["client"].SpanID, found["downstream"].ParentSpanID)
	})
	for _, probe := range probes {
		require.NoError(t, probe.Close())
	}
	_, err = io.WriteString(stdin, "CALL\n")
	require.NoError(t, err)
	waitForClientLine(t, lines, "RESULT=", 10*time.Second)
	select {
	case batch := <-received:
		for _, span := range batch {
			require.NotEqual(t, request.EventTypeCustomSpan, span.Type)
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDynamicGenericProcessHelper(t *testing.T) {
	if os.Getenv("OBI_DYNAMIC_GENERIC_HELPER") != "1" {
		t.Skip("subprocess fixture")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "generic tracer response")
	}))
	defer server.Close()
	fmt.Println("READY=" + server.URL)
	bufio.NewScanner(os.Stdin).Scan()
}
