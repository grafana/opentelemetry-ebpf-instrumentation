// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && jvm_live

package generictracer

import (
	"bufio"
	"bytes"
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

// This live test uses both premain agents. The OTel Java agent owns the manual
// and @WithSpan spans; OBI/eBPF owns only the dynamically selected method spans.
func TestJavaDynamicSpansWithOpenTelemetryAgentLive(t *testing.T) {
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	obiJar := os.Getenv("OBI_JAVA_AGENT_JAR")
	otelJar := os.Getenv("OBI_TEST_OTEL_AGENT_JAR")
	annotationsJar := os.Getenv("OBI_TEST_OTEL_ANNOTATIONS_JAR")
	apiClasspath := os.Getenv("OBI_TEST_OTEL_SDK_CLASSPATH")
	require.NotEmpty(t, obiJar, "set OBI_JAVA_AGENT_JAR to the built agent")
	require.NotEmpty(t, otelJar, "set OBI_TEST_OTEL_AGENT_JAR to an OpenTelemetry Java agent jar")
	require.NotEmpty(t, annotationsJar, "set OBI_TEST_OTEL_ANNOTATIONS_JAR to the annotations jar")
	require.NotEmpty(t, apiClasspath, "set OBI_TEST_OTEL_SDK_CLASSPATH to the application API dependencies")

	directory := t.TempDir()
	source := filepath.Join(directory, "AgentInteropTarget.java")
	require.NoError(t, os.WriteFile(source, []byte(otelAgentTargetSource), 0o600))
	applicationClasspath := annotationsJar + string(os.PathListSeparator) + apiClasspath
	compiled, err := exec.Command("javac", "-cp", applicationClasspath, "-d", directory, source).CombinedOutput()
	require.NoError(t, err, string(compiled))
	command := []string{
		"-javaagent:" + otelJar,
		"-Dotel.traces.exporter=logging",
		"-Dotel.metrics.exporter=none",
		"-Dotel.logs.exporter=none",
		"-javaagent:" + obiJar + "=dynamicInstrumentation=true",
		"-cp", directory + string(os.PathListSeparator) + applicationClasspath,
		"testutil.AgentInteropTarget",
	}
	cmd := exec.Command("java", command...)
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	output, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	finished := false
	t.Cleanup(func() {
		if !finished {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	var tid string
	select {
	case first, ok := <-lines:
		if !ok {
			waitErr := cmd.Wait()
			finished = true
			t.Fatalf("OTel-agent fixture exited during startup: err=%v stderr=%s", waitErr, stderr.String())
		}
		tid = first
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for OTel-agent fixture startup")
	}
	require.Regexp(t, `^[0-9]+$`, tid)
	pid := app.PID(cmd.Process.Pid)

	cfg := obi.DefaultConfig
	cfg.DynamicInstrumentation.Enabled = true
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
	spans := queue.Subscribe(msg.SubscriberName("dynamic-java-otel-agent-test"))
	done := make(chan struct{})
	go func() { defer close(done); pt.Run(ctx, events, queue) }()
	t.Cleanup(func() { cancel(); <-done; queue.Close() })
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "testutil.AgentInteropTarget.*")
		return err == nil && len(names) >= 3
	}, 15*time.Second, 100*time.Millisecond)

	probes := make([]io.Closer, 0, 3)
	for cookie, method := range []string{"work", "duplicateWork", "suppressedWork"} {
		probe, attachErr := target.AttachLiveSpan(pid, fi.Ns(), &config.CustomSpanSpec{
			Name: "obi-" + method,
			On:   config.CustomSpanTarget{FunctionSpan: "testutil.AgentInteropTarget." + method},
		}, uint64(601+cookie), "obi-"+method, 1)
		require.NoError(t, attachErr)
		probes = append(probes, probe)
	}
	defer func() {
		for _, probe := range probes {
			_ = probe.Close()
		}
	}()

	_, err = io.WriteString(input, "CALL\n")
	require.NoError(t, err)
	var outputLines []string
	for {
		line := readLiveJavaLine(t, lines)
		outputLines = append(outputLines, line)
		if line == "DONE" {
			break
		}
	}
	require.Contains(t, outputLines, "RESULTS=8,9,10")
	parent := parseSDKSpanLine(t, outputLines, "SDK_PARENT")
	annotation := parseSDKSpanLine(t, outputLines, "ANNOTATION_PARENT")
	child := parseSDKSpanLine(t, outputLines, "SDK_CHILD")
	duplicateAnnotation := parseSDKSpanLine(t, outputLines, "DUPLICATE_ANNOTATION")
	duplicateChild := parseSDKSpanLine(t, outputLines, "SDK_DUPLICATE_CHILD")
	suppressedChild := parseSDKSpanLine(t, outputLines, "SUPPRESSED_CHILD")
	restored := parseSDKSpanLine(t, outputLines, "SDK_RESTORED")

	// Scenario 1: the OTel agent's @WithSpan annotation creates a child of the
	// active manual SDK span.
	require.Equal(t, parent.trace, annotation.trace)
	require.NotEqual(t, parent.span, annotation.span, "@WithSpan must produce its own active span; output="+strings.Join(outputLines, " "))
	require.Equal(t, parent.span, annotation.parent, "@WithSpan must retain the manual OTel parent")
	require.Equal(t, parent.trace, duplicateAnnotation.trace)

	dynamicSpans := receiveCustomSpans(t, spans, "obi-work", "obi-duplicateWork", "obi-suppressedWork")
	dynamic := dynamicSpans["obi-work"]
	duplicate := dynamicSpans["obi-duplicateWork"]
	suppressed := dynamicSpans["obi-suppressedWork"]

	// Scenario 2: OBI dynamic instrumentation coexists with @WithSpan. On a
	// method instrumented by both agents, the OTel span is nested under OBI's.
	require.Equal(t, annotation.span, dynamic.ParentSpanID.String(), "OBI span should be nested under the @WithSpan span")
	require.Equal(t, parent.trace, dynamic.TraceID.String())
	require.Equal(t, dynamic.SpanID.String(), child.parent, "SDK child should see the OBI span context")
	require.Equal(t, dynamic.TraceID.String(), child.trace)
	require.Equal(t, duplicate.TraceID.String(), duplicateChild.trace)
	require.Equal(t, parent.span, duplicate.ParentSpanID.String(), "OBI span on an annotated method should retain the manual parent")
	require.NotEqual(t, duplicate.SpanID.String(), duplicateAnnotation.span, "the OTel agent should add its own @WithSpan span")
	require.Equal(t, duplicate.SpanID.String(), duplicateAnnotation.parent,
		"when both agents instrument the same method, the OTel annotation span should be nested under OBI's dynamic span")
	require.Equal(t, duplicateAnnotation.span, duplicateChild.parent,
		"the SDK child should inherit the innermost @WithSpan context")

	// Scenario 3: suppressInstrumentation suppresses the OTel agent's @WithSpan
	// only; the independent OBI dynamic span and manual SDK span remain active.
	require.Equal(t, parent.span, suppressed.ParentSpanID.String(),
		"agent suppression should suppress only OTel's @WithSpan, not OBI's dynamic span")
	require.Equal(t, suppressed.SpanID.String(), suppressedChild.parent,
		"a manual SDK span inside suppressed instrumentation should still inherit OBI context")

	// The agent context returns to the manual parent after both instrumentations
	// have exited.
	require.Equal(t, parent.span, restored.span, "agent context must be restored after both instrumentations exit")

	// Let the OTel logging exporter flush on JVM shutdown; OBI spans should not
	// appear in the application's exporter output.
	require.NoError(t, input.Close())
	require.NoError(t, cmd.Wait(), stderr.String())
	finished = true
	exports := stderr.String()
	require.Contains(t, exports, "manual-parent", exports)
	require.Contains(t, exports, "annotation-parent", exports)
	require.Contains(t, exports, "agent-child", exports)
	require.Contains(t, exports, "duplicate-annotation", exports)
	require.Contains(t, exports, "suppressed-agent-child", exports,
		"manual API spans remain recording while agent instrumentation is suppressed")
	require.NotContains(t, exports, "suppressed-annotation",
		"the OpenTelemetry agent's @WithSpan span should be suppressed")
	require.NotContains(t, exports, "obi-work", "OBI/eBPF owns dynamically instrumented spans")
	require.NotContains(t, exports, "obi-duplicateWork", "OBI/eBPF owns dynamically instrumented spans")
	t.Logf("OTel agent/eBPF trace: manual=%s/%s annotation=%s/%s OBI=%s/%s child=%s/%s duplicate OBI=%s/%s suppressed OBI=%s/%s; exporter excludes dynamic and suppressed @WithSpan spans",
		parent.trace, parent.span, annotation.trace, annotation.span, dynamic.TraceID, dynamic.SpanID, child.trace, child.span, duplicate.TraceID, duplicate.SpanID, suppressed.TraceID, suppressed.SpanID)
}

func receiveCustomSpans(t *testing.T, spans <-chan []request.Span, names ...string) map[string]request.Span {
	t.Helper()
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	found := make(map[string]request.Span, len(names))
	deadline := time.After(10 * time.Second)
	for len(found) < len(wanted) {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && wanted[span.Method] {
					found[span.Method] = span
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for OBI custom spans %v; found %v", names, found)
		}
	}
	return found
}

const otelAgentTargetSource = `
package testutil;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class AgentInteropTarget {
  private static final String API = "io.opentelemetry.javaagent.shaded.io.opentelemetry";
  private static Class<?> span;
  private static Class<?> spanContext;
  private static Object tracer;
  private static String annotationTrace;
  private static String annotationSpan;
  private static String annotationParent;
  private static String childTrace;
  private static String childSpan;
  private static String childParent;
  private static String duplicateTrace;
  private static String duplicateSpan;
  private static String duplicateParent;
  private static String duplicateChildTrace;
  private static String duplicateChildSpan;
  private static String duplicateChildParent;
  private static String suppressedChildTrace;
  private static String suppressedChildSpan;
  private static String suppressedChildParent;
  private static int suppressedResult;
  private static String manualTrace;
  private static String manualSpan;

  @WithSpan("annotation-parent")
  public static int annotatedParent(int value) throws Exception {
    Object currentSpan = span.getMethod("current").invoke(null);
    Object currentContext = context(currentSpan);
    annotationTrace = id(currentContext, "getTraceId");
    annotationSpan = id(currentContext, "getSpanId");
    annotationParent = parentSpan(currentSpan);
    return work(value);
  }

  public static int work(int value) throws Exception {
    Object child = start("agent-child");
    childTrace = id(context(child), "getTraceId");
    childSpan = id(context(child), "getSpanId");
    childParent = id(current(), "getSpanId");
    span.getMethod("end").invoke(child);
    return value + 1;
  }

  @WithSpan("duplicate-annotation")
  public static int duplicateWork(int value) throws Exception {
    Object currentSpan = span.getMethod("current").invoke(null);
    Object currentContext = context(currentSpan);
    duplicateTrace = id(currentContext, "getTraceId");
    duplicateSpan = id(currentContext, "getSpanId");
    duplicateParent = parentSpan(currentSpan);
    Object child = start("agent-duplicate-child");
    duplicateChildTrace = id(context(child), "getTraceId");
    duplicateChildSpan = id(context(child), "getSpanId");
    duplicateChildParent = id(current(), "getSpanId");
    span.getMethod("end").invoke(child);
    return value + 2;
  }

  @WithSpan("suppressed-annotation")
  public static int suppressedWork(int value) throws Exception {
    Object child = start("suppressed-agent-child");
    suppressedChildTrace = id(context(child), "getTraceId");
    suppressedChildSpan = id(context(child), "getSpanId");
    suppressedChildParent = id(current(), "getSpanId");
    span.getMethod("end").invoke(child);
    return value + 3;
  }

  private static Object current() throws Exception {
    return span.getMethod("getSpanContext").invoke(span.getMethod("current").invoke(null));
  }

  private static Object start(String name) throws Exception {
    Object builder = Class.forName(API + ".api.trace.Tracer", true, null)
        .getMethod("spanBuilder", String.class).invoke(tracer, name);
    return Class.forName(API + ".api.trace.SpanBuilder", true, null)
        .getMethod("startSpan").invoke(builder);
  }

  private static Object context(Object value) throws Exception {
    return span.getMethod("getSpanContext").invoke(value);
  }

  private static String parentSpan(Object value) throws Exception {
    java.lang.reflect.Method method = value.getClass().getMethod("getParentSpanContext");
    method.setAccessible(true);
    return id(method.invoke(value), "getSpanId");
  }

  private static String id(Object context, String method) throws Exception {
    return (String) spanContext.getMethod(method).invoke(context);
  }

  public static void main(String[] args) throws Exception {
    span = Class.forName(API + ".api.trace.Span", true, null);
    spanContext = Class.forName(API + ".api.trace.SpanContext", true, null);
    tracer = Class.forName(API + ".api.GlobalOpenTelemetry", true, null)
        .getMethod("getTracer", String.class).invoke(null, "obi-live-agent-test");
    Class<?> nativeLib = Class.forName("io.opentelemetry.obi.java.Agent$NativeLib", true, null);
    System.out.println(nativeLib.getMethod("gettid").invoke(null));
    BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
    String line;
    while ((line = input.readLine()) != null) {
      if (!line.equals("CALL")) continue;
      Object parent = start("manual-parent");
      manualTrace = id(context(parent), "getTraceId");
      manualSpan = id(context(parent), "getSpanId");
      Object scope = span.getMethod("makeCurrent").invoke(parent);
      try {
        int left = annotatedParent(7);
        int right = duplicateWork(7);
        Class<?> suppressor = Class.forName(API + ".api.impl.InstrumentationUtil", true, null);
        suppressor.getMethod("suppressInstrumentation", Runnable.class).invoke(null,
            (Runnable) () -> {
              try { suppressedResult = suppressedWork(7); }
              catch (Exception error) { throw new RuntimeException(error); }
            });
        Object restored = current();
        System.out.println("RESULTS=" + left + "," + right + "," + suppressedResult);
        System.out.println("SDK_PARENT|" + manualTrace + "|" + manualSpan + "|0000000000000000");
        System.out.println("ANNOTATION_PARENT|" + annotationTrace + "|" + annotationSpan + "|" + annotationParent);
        System.out.println("SDK_CHILD|" + childTrace + "|" + childSpan + "|" + childParent);
        System.out.println("DUPLICATE_ANNOTATION|" + duplicateTrace + "|" + duplicateSpan + "|" + duplicateParent);
        System.out.println("SDK_DUPLICATE_CHILD|" + duplicateChildTrace + "|" + duplicateChildSpan + "|" + duplicateChildParent);
        System.out.println("SUPPRESSED_CHILD|" + suppressedChildTrace + "|" + suppressedChildSpan + "|" + suppressedChildParent);
        System.out.println("SDK_RESTORED|" + id(restored, "getTraceId") + "|" + id(restored, "getSpanId") + "|-");
      } finally {
        Class.forName(API + ".context.Scope", true, null).getMethod("close").invoke(scope);
        span.getMethod("end").invoke(parent);
      }
      System.out.println("DONE");
      break;
    }
  }
}
`
