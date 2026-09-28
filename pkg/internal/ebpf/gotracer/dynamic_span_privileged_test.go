// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"bufio"
	"context"
	"encoding/json"
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
	_, dwarfErr := info.ELF().DWARF()
	info.SetAutoServiceName("binary-fallback")
	info.SetAutoServiceNamespace("k8s-fallback")
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
	count := func(probe io.Closer) uint64 {
		t.Helper()
		counter, ok := probe.(interface{ Invocations() (uint64, error) })
		require.True(t, ok)
		value, err := counter.Invocations()
		require.NoError(t, err)
		return value
	}
	var probes []io.Closer
	for index, name := range []string{"outer", "inner", "outerAsync", "outerDetached", "echo", "echoAsync", "HTTPHandler", "sdkOuter", "sdkInner"} {
		probe, err := tracer.AttachLiveSpan(pid, info.Ns(), &config.CustomSpanSpec{Name: name, On: config.CustomSpanTarget{FunctionSpan: "main." + name}}, uint64(index+1), name, 1)
		require.NoError(t, err)
		require.Zero(t, count(probe))
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
			before := count(probes[1])
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
			require.Equal(t, before+1, count(probes[1]), "one entry per call, without counting returns")
			outer, inner := found[test.outer], found["inner"]
			if test.http {
				require.Equal(t, found["server"].SpanID, outer.ParentSpanID)
				require.Equal(t, found["server"].TraceID, outer.TraceID)
			} else {
				require.Equal(t, "otel-remotedice", outer.Service.UID.Name)
				require.Equal(t, "manual", outer.Service.UID.Namespace)
				require.Equal(t, result[0], outer.TraceID.String())
				require.Equal(t, result[1], outer.ParentSpanID.String())
			}
			require.Equal(t, outer.SpanID, inner.ParentSpanID)
			require.Equal(t, outer.TraceID, inner.TraceID)
			if test.outer == "outerDetached" {
				require.Less(t, outer.End, inner.Start)
			}
			require.Less(t, inner.Start, inner.End)
			if dwarfErr == nil {
				require.Equal(t, "hello", inner.CustomSpan.Attrs["arg0"])
				require.Equal(t, "7", inner.CustomSpan.Attrs["arg1"])
				require.Equal(t, "hello!", inner.CustomSpan.Attrs["return0"])
				require.Equal(t, "8", inner.CustomSpan.Attrs["return1"])
			} else {
				for _, name := range []string{"arg0", "arg1", "return0", "return1"} {
					require.NotContains(t, inner.CustomSpan.Attrs, name, "stripped free functions have no retained argument metadata")
				}
			}
		})
	}
	for _, command := range []string{"SDK_CLIENT", "SDK_CLIENT_ASYNC", "SDK_CLIENT_INHERITED"} {
		t.Run(command, func(t *testing.T) {
			_, err := io.WriteString(stdin, command+"\n")
			require.NoError(t, err)
			var result struct {
				Started, Exported []struct{ Name, Trace, ID, Parent string }
			}
			line := waitForClientLine(t, lines, "SDK_EXPORTED=", 10*time.Second)
			require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "SDK_EXPORTED=")), &result))
			found := map[string]request.Span{}
			timeout := time.After(10 * time.Second)
			expected := 2
			if command == "SDK_CLIENT_INHERITED" {
				expected = 1
			}
			for len(found) < expected {
				select {
				case batch := <-received:
					for _, span := range batch {
						if span.Type == request.EventTypeCustomSpan {
							found[span.Method] = span
						}
					}
				case <-timeout:
					t.Fatalf("missing dynamic spans: %v", found)
				}
			}
			outer, inner := found["sdkOuter"], found["sdkInner"]
			if command == "SDK_CLIENT_INHERITED" {
				outer = inner
			} else {
				require.Equal(t, outer.SpanID, inner.ParentSpanID)
				require.Equal(t, outer.TraceID, inner.TraceID)
			}
			wantParent := inner.SpanID.String()
			if !goTracer.supportsContextPropagation() {
				wantParent = outer.ParentSpanID.String()
			}
			for _, spans := range [][]struct{ Name, Trace, ID, Parent string }{result.Started, result.Exported} {
				require.Len(t, spans, 8)
				ids := map[string]string{}
				for _, span := range spans {
					ids[span.Name] = span.ID
				}
				for _, span := range spans {
					switch span.Name {
					case "sdk.server":
						require.Equal(t, outer.ParentSpanID.String(), span.ID)
						require.Equal(t, outer.TraceID.String(), span.Trace)
						require.Equal(t, "0000000000000000", span.Parent)
					case "sdk.client", "sdk.sibling":
						require.Equal(t, wantParent, span.Parent, span.Name)
						require.Equal(t, inner.TraceID.String(), span.Trace)
					case "sdk.grandchild":
						require.Equal(t, ids["sdk.client"], span.Parent)
					case "sdk.newroot":
						require.Equal(t, "0000000000000000", span.Parent)
						require.NotEqual(t, inner.TraceID.String(), span.Trace)
					case "sdk.unrelated":
						require.Equal(t, "0100000000000000", span.Parent)
					case "sdk.remote", "sdk.after":
						require.Equal(t, ids["sdk.server"], span.Parent, span.Name)
					default:
						t.Fatalf("unexpected SDK span: %v", span)
					}
				}
			}
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
		probe, err := genericTracer.AttachLiveSpan(otherPID, otherInfo.Ns(), &config.CustomSpanSpec{
			Name: "generic", On: config.CustomSpanTarget{FunctionNoRet: "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer.dynamicGenericHandler"},
		}, 200, "generic", 1)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, probe.Close()) })
		require.Zero(t, count(probe))
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, otherURL+"/generic", nil)
		require.NoError(t, err)
		response, err := client.Do(req)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Positive(t, count(probe), "generic tracer dynamic probes must count entries too")
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

	for _, mode := range []string{"HTTP_ECHO", "SDK_ECHO"} {
		t.Run(mode, func(t *testing.T) {
			expected := 10
			var sdkContext []string
			if mode == "SDK_ECHO" {
				expected -= 2
				_, err := io.WriteString(stdin, "SDK_ECHO\n")
				require.NoError(t, err)
				sdkContext = strings.Fields(strings.TrimPrefix(waitForClientLine(t, lines, "SDK_RESULT=", 10*time.Second), "SDK_RESULT="))
			} else {
				client := &http.Client{Timeout: 10 * time.Second}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, strings.TrimPrefix(ready, "READY=")+"/echo", nil)
				require.NoError(t, err)
				response, err := client.Do(req)
				require.NoError(t, err)
				require.Equal(t, http.StatusNonAuthoritativeInfo, response.StatusCode)
				require.NoError(t, response.Body.Close())
			}
			found := map[string]request.Span{}
			timeout := time.After(10 * time.Second)
			for len(found) < expected {
				select {
				case batch := <-received:
					for _, span := range batch {
						switch {
						case span.Type == request.EventTypeCustomSpan:
							found[span.Method] = span
						case span.Type == request.EventTypeHTTP:
							found["server:"+span.Path] = span
						case span.Type == request.EventTypeHTTPClient:
							found["client:"+span.Path] = span
						}
					}
				case <-timeout:
					t.Fatalf("expected the complete echo trace, got %v", found)
				}
			}
			for name, span := range found {
				t.Logf("%s: trace=%s span=%s parent=%s", name, span.TraceID, span.SpanID, span.ParentSpanID)
			}
			outer, inner := found["echoAsync"], found["echo"]
			if mode == "SDK_ECHO" {
				require.Equal(t, sdkContext[0], outer.TraceID.String())
				require.Equal(t, sdkContext[1], outer.ParentSpanID.String())
			} else {
				server, handler := found["server:/echo"], found["HTTPHandler"]
				require.False(t, server.ParentSpanID.IsValid(), "the external request has no incoming trace context")
				require.Equal(t, http.StatusNonAuthoritativeInfo, server.Status, "the child goroutine writes the server response")
				require.Equal(t, server.TraceID, handler.TraceID)
				require.Equal(t, server.SpanID, handler.ParentSpanID)
				require.Equal(t, handler.TraceID, outer.TraceID)
				require.Equal(t, handler.SpanID, outer.ParentSpanID)
			}
			require.Equal(t, outer.SpanID, inner.ParentSpanID)
			require.Equal(t, inner.SpanID, found["client:/echoBack"].ParentSpanID, "client call must use the active dynamic span")
			require.Equal(t, outer.SpanID, found["client:/afterEcho"].ParentSpanID, "return must restore the inherited outer span")
			require.Equal(t, outer.ParentSpanID, found["client:/afterAsync"].ParentSpanID, "return must restore the enclosing context")
			for _, path := range []string{"/echoBack", "/afterEcho", "/afterAsync"} {
				client, downstream := found["client:"+path], found["server:"+path]
				require.Equal(t, outer.TraceID, client.TraceID)
				require.Equal(t, client.TraceID, downstream.TraceID)
				require.Equal(t, client.SpanID, downstream.ParentSpanID)
			}
		})
	}

	t.Run("DETACH_ACTIVE", func(t *testing.T) {
		spec := &config.CustomSpanSpec{Name: "blocked", On: config.CustomSpanTarget{FunctionSpan: "main.blockedEcho"}}
		probe, err := tracer.AttachLiveSpan(pid, info.Ns(), spec, 100, "blocked", 1)
		require.NoError(t, err)
		t.Cleanup(func() { _ = probe.Close() })
		_, err = io.WriteString(stdin, "BLOCKED\n")
		require.NoError(t, err)
		parent := strings.Fields(strings.TrimPrefix(waitForClientLine(t, lines, "BLOCKED_CONTEXT=", 10*time.Second), "BLOCKED_CONTEXT="))
		waitForClientLine(t, lines, "BLOCKED", 10*time.Second)
		// A new goroutine can retry the entry after runtime.morestack grows its stack.
		require.Positive(t, count(probe), "count entry hits before the call returns or emits a span")
		require.NoError(t, probe.Close())
		_, err = probe.(interface{ Invocations() (uint64, error) }).Invocations()
		require.Error(t, err, "detachment must delete the BPF counter")
		replacement, err := tracer.AttachLiveSpan(pid, info.Ns(), spec, 101, "blocked", 2)
		require.NoError(t, err)
		t.Cleanup(func() { _ = replacement.Close() })
		_, err = io.WriteString(stdin, "RELEASE\n")
		require.NoError(t, err)
		waitForClientLine(t, lines, "RELEASED", 10*time.Second)
		require.Zero(t, count(replacement), "returning a detached invocation must not hit a replacement counter")
		found := map[request.EventType]request.Span{}
		timeout := time.After(10 * time.Second)
		for len(found) < 2 {
			select {
			case batch := <-received:
				for _, span := range batch {
					require.NotEqual(t, request.EventTypeCustomSpan, span.Type, "a detached invocation must not emit a span")
					if span.Path == "/detachedProbe" {
						found[span.Type] = span
					}
				}
			case <-timeout:
				t.Fatal("missing HTTP spans after removing an active dynamic probe")
			}
		}
		client, server := found[request.EventTypeHTTPClient], found[request.EventTypeHTTP]
		require.Equal(t, parent[0], client.TraceID.String())
		require.Equal(t, parent[1], client.ParentSpanID.String(), "detachment must restore the SDK parent even when the spec slot is reused")
		require.Equal(t, client.TraceID, server.TraceID)
		require.Equal(t, client.SpanID, server.ParentSpanID)
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
	server := httptest.NewServer(http.HandlerFunc(dynamicGenericHandler))
	defer server.Close()
	fmt.Println("READY=" + server.URL)
	bufio.NewScanner(os.Stdin).Scan()
}

//go:noinline
func dynamicGenericHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "generic tracer response")
}
