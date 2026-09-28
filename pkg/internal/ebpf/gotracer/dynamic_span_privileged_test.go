// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"context"
	"io"
	"log/slog"
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
	waitForClientLine(t, lines, "READY", time.Second*10)
	pid := app.PID(command.Process.Pid)
	cfg := obi.DefaultConfig
	cfg.DynamicInstrumentation.Enabled = true
	cfg.EBPF.PopulateTraceContext = true
	cfg.EBPF.BatchLength = 1
	cfg.EBPF.BatchTimeout = 10 * time.Millisecond
	pids := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	goTracer := New(pids, &cfg, imetrics.NoopReporter{})
	generic := generictracer.New(pids, &cfg, imetrics.NoopReporter{})
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = pids
	tracer := ebpftracer.NewProcessTracer(ebpftracer.Go, []ebpftracer.Tracer{goTracer, generic}, &cfg, imetrics.NoopReporter{})
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
	for index, name := range []string{"outer", "inner"} {
		probe, err := tracer.AttachLiveSpan(pid, info.Ns(), &config.CustomSpanSpec{Name: name, On: config.CustomSpanTarget{FunctionSpan: "main." + name}}, uint64(index+1), name, 1)
		require.NoError(t, err)
		probes = append(probes, probe)
		t.Cleanup(func() { _ = probe.Close() })
	}
	_, err = io.WriteString(stdin, "CALL\n")
	require.NoError(t, err)
	result := strings.Fields(strings.TrimPrefix(waitForClientLine(t, lines, "RESULT=", 10*time.Second), "RESULT="))
	found := map[string]request.Span{}
	timeout := time.After(10 * time.Second)
	for len(found) < 2 {
		select {
		case batch := <-received:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan {
					found[span.Method] = span
				}
			}
		case <-timeout:
			t.Fatalf("expected two dynamic spans, got %v", found)
		}
	}
	outer, inner := found["outer"], found["inner"]
	require.Equal(t, result[0], outer.TraceID.String())
	require.Equal(t, result[1], outer.ParentSpanID.String())
	require.Equal(t, outer.SpanID, inner.ParentSpanID)
	require.Equal(t, outer.TraceID, inner.TraceID)
	require.Less(t, inner.Start, inner.End)
	require.Equal(t, "hello", inner.CustomSpan.Attrs["arg0"])
	require.Equal(t, "7", inner.CustomSpan.Attrs["arg1"])
	require.Equal(t, "hello!", inner.CustomSpan.Attrs["return0"])
	require.Equal(t, "8", inner.CustomSpan.Attrs["return1"])
	_, err = io.WriteString(stdin, "HTTP\n")
	require.NoError(t, err)
	waitForClientLine(t, lines, "HTTP_RESULT=", 10*time.Second)
	httpSpans := map[string]request.Span{}
	timeout = time.After(10 * time.Second)
	for len(httpSpans) < 3 {
		select {
		case batch := <-received:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan {
					httpSpans[span.Method] = span
				}
				if span.Type == request.EventTypeHTTP {
					httpSpans["server"] = span
				}
			}
		case <-timeout:
			t.Fatalf("expected a server span and two dynamic spans, got %v", httpSpans)
		}
	}
	require.Equal(t, httpSpans["server"].SpanID, httpSpans["outer"].ParentSpanID)
	require.Equal(t, httpSpans["server"].TraceID, httpSpans["outer"].TraceID)
	require.Equal(t, httpSpans["outer"].SpanID, httpSpans["inner"].ParentSpanID)
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
