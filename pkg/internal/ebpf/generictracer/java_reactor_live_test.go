// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && jvm_live

package generictracer

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// TestReactorDynamicSpanParentageLive exercises the real Java-agent -> ioctl
// -> OBI/eBPF path for an application SDK parent, a dynamically instrumented
// work method, and a dynamically instrumented Reactor worker method after
// publishOn(Schedulers.parallel()). It covers this pinned Reactor scenario
// only; it does not establish general Reactor or Micrometer context support.
//
// Keep test-only dependencies out of the module/runtime dependencies. Set
// OBI_TEST_REACTOR_CLASSPATH to a colon-separated classpath containing Reactor
// Core 3.8.7, Reactive Streams 1.0.4, and OpenTelemetry API/SDK 1.55.0 jars.
// For example, after placing those jars in $D, set it with:
//
//	export OBI_TEST_REACTOR_CLASSPATH="$(printf '%s:' "$D"/*.jar)"
//
// The test skips when the variable is absent.
func TestReactorDynamicSpanParentageLive(t *testing.T) {
	classpath := os.Getenv("OBI_TEST_REACTOR_CLASSPATH")
	if classpath == "" {
		t.Skip("set OBI_TEST_REACTOR_CLASSPATH to Reactor Core, Reactive Streams, and OpenTelemetry SDK jars")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	jar := os.Getenv("OBI_JAVA_AGENT_JAR")
	require.NotEmpty(t, jar, "set OBI_JAVA_AGENT_JAR to the built agent")

	directory := t.TempDir()
	source := filepath.Join(directory, "ReactorProbe.java")
	require.NoError(t, os.WriteFile(source, []byte(reactorProbeSource), 0o600))
	compiled, err := exec.Command("javac", "-cp", classpath, "-d", directory, source).CombinedOutput()
	require.NoError(t, err, string(compiled))

	cmd := exec.Command("java", "-javaagent:"+jar+"=dynamicInstrumentation=true", "-cp", directory+string(os.PathListSeparator)+classpath, "ReactorProbe")
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	ready := strings.Split(readLiveJavaLine(t, lines), "|")
	require.Len(t, ready, 2)
	require.Equal(t, "READY", ready[0])
	parentSpanID := ready[1]
	require.Regexp(t, `^[0-9a-f]{16}$`, parentSpanID)

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
	spans := queue.Subscribe(msg.SubscriberName("reactor-dynamic-live-test"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		pt.Run(ctx, events, queue)
	}()
	t.Cleanup(func() { cancel(); <-done; queue.Close() })

	for _, method := range []string{"work", "worker"} {
		method := method
		require.Eventually(t, func() bool {
			names, err := target.ResolveLiveSymbols(pid, "ReactorProbe."+method)
			return err == nil && len(names) == 1
		}, 15*time.Second, 100*time.Millisecond)
	}
	probes := make([]io.Closer, 0, 2)
	for i, method := range []string{"work", "worker"} {
		spec := config.CustomSpanSpec{
			Name: "reactor-" + method,
			On:   config.CustomSpanTarget{FunctionSpan: "ReactorProbe." + method},
		}
		probe, err := target.AttachLiveSpan(pid, fi.Ns(), &spec, uint64(i+1), method, 1)
		require.NoError(t, err)
		probes = append(probes, probe)
	}
	t.Cleanup(func() {
		for _, probe := range probes {
			_ = probe.Close()
		}
	})

	_, err = io.WriteString(input, "GO\n")
	require.NoError(t, err)
	var outputLines []string
	for {
		line := readLiveJavaLine(t, lines)
		outputLines = append(outputLines, line)
		if line == "DONE" {
			break
		}
	}
	workerSpanID := ""
	for _, line := range outputLines {
		if strings.HasPrefix(line, "WORKER_OTEL=") {
			workerSpanID = strings.TrimPrefix(line, "WORKER_OTEL=")
		}
	}
	require.Regexp(t, `^[0-9a-f]{16}$`, workerSpanID, "Reactor worker should observe its dynamic OTel context")

	var workSpan, workerSpan request.Span
	var seen []request.Span
	deadline := time.After(15 * time.Second)
	for !workSpan.SpanID.IsValid() || !workerSpan.SpanID.IsValid() {
		select {
		case batch := <-spans:
			for _, span := range batch {
				seen = append(seen, span)
				if span.Type != request.EventTypeCustomSpan {
					continue
				}
				switch span.Method {
				case "reactor-work":
					workSpan = span
				case "reactor-worker":
					workerSpan = span
				}
			}
		case <-deadline:
			t.Fatalf("timed out awaiting Reactor dynamic spans: work=%+v worker=%+v Java=%v events=%+v", workSpan, workerSpan, outputLines, seen)
		}
	}

	t.Logf("Reactor dynamic spans: SDK parent=%s work=%s/%s parent=%s worker=%s/%s parent=%s worker Span.current=%s",
		parentSpanID, workSpan.TraceID, workSpan.SpanID, workSpan.ParentSpanID,
		workerSpan.TraceID, workerSpan.SpanID, workerSpan.ParentSpanID, workerSpanID)
	require.Equal(t, parentSpanID, workSpan.ParentSpanID.String(), "dynamic work span should inherit the active SDK parent")
	require.Equal(t, workSpan.TraceID, workerSpan.TraceID, "Reactor worker span should remain in the work trace")
	require.Equal(t, workSpan.SpanID, workerSpan.ParentSpanID, "Reactor worker span should be parented to the active work span")
	require.Equal(t, workerSpan.SpanID.String(), workerSpanID, "worker Span.current should expose its dynamic span context")
}

const reactorProbeSource = `
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

public final class ReactorProbe {
  private static final SdkTracerProvider PROVIDER = SdkTracerProvider.builder().build();
  private static final Tracer TRACER = PROVIDER.get("reactor-probe");
  private static String parentSpanId;
  private static String workerSpanId;

  public static void main(String[] args) throws Exception {
    Span parent = TRACER.spanBuilder("server").startSpan();
    parentSpanId = parent.getSpanContext().getSpanId();
    try (Scope ignored = parent.makeCurrent()) {
      System.out.println("READY|" + parentSpanId);
      System.out.flush();
      new BufferedReader(new InputStreamReader(System.in)).readLine();
      work();
    } finally {
      parent.end();
      Schedulers.shutdownNow();
      PROVIDER.close();
    }
    System.out.println("PARENT=" + parentSpanId);
    System.out.println("WORKER_OTEL=" + workerSpanId);
    System.out.println("DONE");
  }

  public static void work() {
    Mono.just(1).publishOn(Schedulers.parallel()).map(ignored -> worker()).block();
  }

  public static int worker() {
    workerSpanId = Span.current().getSpanContext().getSpanId();
    return 1;
  }
}
`
