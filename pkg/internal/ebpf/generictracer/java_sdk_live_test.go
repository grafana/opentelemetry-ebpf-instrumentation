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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/liveprober"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// This test exercises the actual javaagent -> ioctl -> OBI/eBPF path. The SDK
// classpath is supplied by OBI_TEST_OTEL_SDK_CLASSPATH to keep the Go package
// independent of Gradle's Java test dependencies.
func TestJavaDynamicSpansWithStandaloneSDKLive(t *testing.T) {
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	jar := os.Getenv("OBI_JAVA_AGENT_JAR")
	require.NotEmpty(t, jar, "set OBI_JAVA_AGENT_JAR to the built agent")
	sdkClasspath := os.Getenv("OBI_TEST_OTEL_SDK_CLASSPATH")
	require.NotEmpty(t, sdkClasspath, "set OBI_TEST_OTEL_SDK_CLASSPATH to the application SDK jars")

	directory := t.TempDir()
	source := filepath.Join(directory, "StandaloneSdkTarget.java")
	require.NoError(t, os.WriteFile(source, []byte(standaloneSDKTargetSource), 0o600))
	isolatedSource := filepath.Join(directory, "IsolatedSdkTarget.java")
	require.NoError(t, os.WriteFile(isolatedSource, []byte(isolatedSDKTargetSource), 0o600))
	compiled, err := exec.Command("javac", "-cp", sdkClasspath, "-d", directory, source, isolatedSource).CombinedOutput()
	require.NoError(t, err, string(compiled))
	cmd := exec.Command("java", "-javaagent:"+jar+"=dynamicInstrumentation=true", "-cp", directory+string(os.PathListSeparator)+sdkClasspath, "StandaloneSdkTarget")
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
	tid := readLiveJavaLine(t, lines)
	require.Regexp(t, `^[0-9]+$`, tid)
	pid := app.PID(cmd.Process.Pid)

	cfg := obi.DefaultConfig
	require.NoError(t, yaml.Unmarshal([]byte(`dynamic_instrumentation:
  enabled: true
  rules:
    - service:
        - open_ports: "8180"
      spans:
        - name: dynamic-work
          on:
            function_span: StandaloneSdkTarget.work
        - name: isolated-dynamic-work
          on:
            function_span: IsolatedSdkTarget.work
        - name: isolated-dynamic-throw
          on:
            function_span: IsolatedSdkTarget.workThrows
`), &cfg))
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
	spans := queue.Subscribe(msg.SubscriberName("dynamic-java-sdk-test"))
	done := make(chan struct{})
	go func() { defer close(done); pt.Run(ctx, events, queue) }()
	t.Cleanup(func() { cancel(); <-done; queue.Close() })
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "StandaloneSdkTarget.work")
		return err == nil && len(names) == 1
	}, 15*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "IsolatedSdkTarget.work")
		return err == nil && len(names) == 1
	}, 15*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool {
		names, err := target.ResolveLiveSymbols(pid, "IsolatedSdkTarget.workThrows")
		return err == nil && len(names) == 1
	}, 15*time.Second, 100*time.Millisecond)
	service := cfg.DynamicInstrumentation.Rules[0].Service
	dynamicManager := liveprober.New()
	dynamicManager.Configure(cfg.DynamicInstrumentation, nil, imetrics.NoopReporter{})
	dynamicManager.ObserveProcess(int(pid), func(criteria services.GlobDefinitionCriteria) bool {
		return slices.ContainsFunc(criteria, func(selector services.GlobAttributes) bool {
			return selector.OpenPorts.Matches(8180)
		})
	})
	require.NoError(t, dynamicManager.RegisterTarget(int(pid), fi.Ns(), target, nil))
	t.Cleanup(func() { require.NoError(t, dynamicManager.Close()) })
	require.NoError(t, dynamicManager.SetConfigRules(cfg.DynamicInstrumentation.Rules))

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
	require.Contains(t, outputLines, "RESULT=8")
	parent := parseSDKSpanLine(t, outputLines, "SDK_PARENT")
	child := parseSDKSpanLine(t, outputLines, "SDK_CHILD")
	restored := parseSDKSpanLine(t, outputLines, "SDK_RESTORED")
	exported := parseSDKExports(t, outputLines)
	require.Equal(t, parent.span, restored.span, "dynamic scope must restore the manual SDK parent")
	require.Equal(t, parent.trace, child.trace)
	require.ElementsMatch(t, []string{"manual-parent", "sdk-child"}, exported.names,
		"the application SDK must export its own spans, not OBI's dynamic method span")

	var dynamic request.Span
	var seen []request.Span
	deadline := time.After(10 * time.Second)
	for !dynamic.SpanID.IsValid() {
		select {
		case batch := <-spans:
			seen = append(seen, batch...)
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && span.Method == "dynamic-work" {
					dynamic = span
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for OBI dynamic method span; configured probes=%+v output=%v events=%+v",
				dynamicManager.ListFunctions(service), outputLines, seen)
		}
	}
	if !dynamic.SpanID.IsValid() {
		t.Fatalf("missing OBI dynamic span in batch: %+v", dynamic)
	}
	t.Logf("standalone SDK export: parent=%s/%s dynamic=%s/%s parent=%s sdk-child=%s/%s parent=%s; exported SDK spans=%v",
		parent.trace, parent.span, dynamic.TraceID, dynamic.SpanID, dynamic.ParentSpanID, child.trace, child.span, child.parent, exported.names)
	require.Equal(t, parent.trace, dynamic.TraceID.String())
	require.Equal(t, parent.span, dynamic.ParentSpanID.String(), "OBI span must use the active application SDK span as parent")
	require.Equal(t, child.trace, dynamic.TraceID.String())
	require.Equal(t, dynamic.SpanID.String(), child.parent, "SDK child must inherit the OBI dynamic span context")

	_, err = io.WriteString(input, "CALL_ISOLATED\n")
	require.NoError(t, err)
	var isolatedOutput []string
	for {
		line := readLiveJavaLine(t, lines)
		isolatedOutput = append(isolatedOutput, line)
		if line == "ISOLATED_DONE" {
			break
		}
	}
	require.Contains(t, isolatedOutput, "ISOLATED_API_SEPARATE|true",
		"the plugin's OTel API must be loaded by a distinct class loader")
	isolatedParent := parseSDKSpanLine(t, isolatedOutput, "ISOLATED_PARENT")
	isolatedChild := parseSDKSpanLine(t, isolatedOutput, "ISOLATED_CHILD")
	isolatedRestored := parseSDKSpanLine(t, isolatedOutput, "ISOLATED_RESTORED")
	isolatedExceptionRestored := parseSDKSpanLine(t, isolatedOutput, "ISOLATED_EXCEPTION_RESTORED")
	require.Equal(t, isolatedParent.span, isolatedRestored.span,
		"the child-loader SDK context must be restored after OBI exits")
	require.Equal(t, isolatedParent.span, isolatedExceptionRestored.span,
		"the child-loader SDK context must be restored after an instrumented method throws")
	var isolatedExportNames []string
	for _, line := range isolatedOutput {
		parts := strings.Split(line, "|")
		if len(parts) == 5 && parts[0] == "ISOLATED_EXPORT" {
			isolatedExportNames = append(isolatedExportNames, parts[1])
		}
	}
	require.ElementsMatch(t, []string{"isolated-manual-parent", "isolated-sdk-child"}, isolatedExportNames,
		"the child-loader SDK exporter owns its spans, not OBI's dynamic method span")
	isolatedDynamics := receiveCustomSpans(t, spans, "isolated-dynamic-work", "isolated-dynamic-throw")
	isolatedDynamic := isolatedDynamics["isolated-dynamic-work"]
	isolatedThrow := isolatedDynamics["isolated-dynamic-throw"]
	require.Equal(t, isolatedParent.trace, isolatedDynamic.TraceID.String())
	require.Equal(t, isolatedParent.span, isolatedDynamic.ParentSpanID.String(),
		"OBI must read the active parent from the target's isolated API class loader")
	require.Equal(t, isolatedParent.trace, isolatedThrow.TraceID.String())
	require.Equal(t, isolatedParent.span, isolatedThrow.ParentSpanID.String(),
		"a throwing method must retain and restore the isolated SDK parent")
	require.Equal(t, isolatedDynamic.TraceID.String(), isolatedChild.trace)
	require.Equal(t, isolatedDynamic.SpanID.String(), isolatedChild.parent,
		"the isolated SDK child must inherit the OBI method context")
	t.Logf("isolated SDK class-loader trace: parent=%s/%s OBI=%s/%s SDK child=%s/%s parent=%s; child-loaded SDK exporter owns only its manual and child spans",
		isolatedParent.trace, isolatedParent.span, isolatedDynamic.TraceID, isolatedDynamic.SpanID,
		isolatedChild.trace, isolatedChild.span, isolatedChild.parent)

	_, err = io.WriteString(input, "CALL_UNSAMPLED\n")
	require.NoError(t, err)
	var unsampledOutput []string
	for {
		line := readLiveJavaLine(t, lines)
		unsampledOutput = append(unsampledOutput, line)
		if line == "UNSAMPLED_DONE" {
			break
		}
	}
	unsampledParent := parseSDKSpanLine(t, unsampledOutput, "UNSAMPLED_PARENT")
	unsampledChild := parseSDKSpanLine(t, unsampledOutput, "UNSAMPLED_CHILD")
	require.Contains(t, unsampledOutput, "SDK_EXPORT_COUNT|0",
		"an always-off parent must suppress SDK export of its child")
	unsampled := receiveNamedCustomSpan(t, spans, "dynamic-work")
	require.Equal(t, unsampledParent.trace, unsampled.TraceID.String())
	require.Equal(t, unsampledParent.span, unsampled.ParentSpanID.String())
	require.Equal(t, unsampledParent.trace, unsampledChild.trace)
	require.Equal(t, unsampled.SpanID.String(), unsampledChild.parent,
		"the unsampled SDK child should inherit OBI's dynamic method context")
	require.Zero(t, unsampled.TraceFlags&1, "OBI should preserve the unsampled trace flag")
	require.NoError(t, dynamicManager.SetConfigRules(nil))
	require.Empty(t, dynamicManager.ListFunctions(service), "removing the config rule must detach live Java probes")
	t.Logf("unsampled SDK parent=%s/%s OBI dynamic=%s/%s flags=%d SDK exports=0",
		unsampledParent.trace, unsampledParent.span, unsampled.TraceID, unsampled.SpanID, unsampled.TraceFlags)
}

func receiveNamedCustomSpan(t *testing.T, spans <-chan []request.Span, name string) request.Span {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case batch := <-spans:
			for _, span := range batch {
				if span.Type == request.EventTypeCustomSpan && span.Method == name {
					return span
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for OBI custom span %q", name)
			return request.Span{}
		}
	}
}

type sdkSpanLine struct{ trace, span, parent string }

func readLiveJavaLine(t *testing.T, lines <-chan string) string {
	t.Helper()
	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatal("Java process exited before completing the live scenario")
		}
		return line
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for Java fixture output")
		return ""
	}
}

func parseSDKSpanLine(t *testing.T, lines []string, key string) sdkSpanLine {
	t.Helper()
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) == 4 && parts[0] == key {
			return sdkSpanLine{trace: parts[1], span: parts[2], parent: parts[3]}
		}
	}
	t.Fatalf("missing %s in Java output: %v", key, lines)
	return sdkSpanLine{}
}

type sdkExportSummary struct{ names []string }

func parseSDKExports(t *testing.T, lines []string) sdkExportSummary {
	t.Helper()
	var result sdkExportSummary
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) == 5 && parts[0] == "SDK_EXPORT" {
			result.names = append(result.names, parts[1])
		}
	}
	require.Len(t, result.names, 2, fmt.Sprintf("unexpected SDK exporter output: %v", lines))
	return result
}

const standaloneSDKTargetSource = `
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class StandaloneSdkTarget {
  private static Class<?> isolatedTarget;

  private static final class ChildFirstLoader extends URLClassLoader {
    ChildFirstLoader(URL[] urls, ClassLoader parent) { super(urls, parent); }

    @Override protected synchronized Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      Class<?> loaded = findLoadedClass(name);
      if (loaded == null && (name.startsWith("io.opentelemetry.") || name.equals("IsolatedSdkTarget"))) {
        try { loaded = findClass(name); } catch (ClassNotFoundException ignored) {}
      }
      if (loaded == null) loaded = super.loadClass(name, false);
      if (resolve) resolveClass(loaded);
      return loaded;
    }
  }

  private static URL[] isolatedClasspath() throws Exception {
    List<URL> urls = new ArrayList<>();
    for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
      if (entry.endsWith("*")) {
        File directory = new File(entry.substring(0, entry.length() - 1));
        File[] jars = directory.listFiles((dir, name) -> name.endsWith(".jar"));
        if (jars != null) for (File jar : jars) urls.add(jar.toURI().toURL());
      } else {
        urls.add(new File(entry).toURI().toURL());
      }
    }
    return urls.toArray(new URL[0]);
  }

  private static final InMemorySpanExporter EXPORTER = InMemorySpanExporter.create();
  private static final SdkTracerProvider PROVIDER = SdkTracerProvider.builder()
      .addSpanProcessor(SimpleSpanProcessor.create(EXPORTER)).build();
  private static final Tracer TRACER;
  static {
    OpenTelemetrySdk.builder().setTracerProvider(PROVIDER).buildAndRegisterGlobal();
    TRACER = GlobalOpenTelemetry.getTracer("obi-standalone-sdk-live-test");
  }
  private static String parentTrace;
  private static String parentSpan;
  private static String childTrace;
  private static String childSpan;
  private static String childParent;

  public static int work(int value) {
    Span child = TRACER.spanBuilder("sdk-child").startSpan();
    SpanContext context = child.getSpanContext();
    childTrace = context.getTraceId();
    childSpan = context.getSpanId();
    childParent = Span.current().getSpanContext().getSpanId();
    child.end();
    return value + 1;
  }

  public static void main(String[] args) throws Exception {
    ServerSocket service = new ServerSocket(8180);
    ChildFirstLoader isolatedLoader = new ChildFirstLoader(isolatedClasspath(), StandaloneSdkTarget.class.getClassLoader());
    isolatedTarget = Class.forName("IsolatedSdkTarget", true, isolatedLoader);
    Class<?> nativeLib = Class.forName("io.opentelemetry.obi.java.Agent$NativeLib", true, null);
    System.out.println(nativeLib.getMethod("gettid").invoke(null));
    BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
    String line;
    while ((line = input.readLine()) != null) {
      if (line.equals("CALL")) {
        EXPORTER.reset();
        Span parent = TRACER.spanBuilder("manual-parent").startSpan();
        parentTrace = parent.getSpanContext().getTraceId();
        parentSpan = parent.getSpanContext().getSpanId();
        try (Scope ignored = parent.makeCurrent()) {
          System.out.println("RESULT=" + work(7));
          System.out.println("SDK_PARENT|" + parentTrace + "|" + parentSpan + "|0000000000000000");
          System.out.println("SDK_CHILD|" + childTrace + "|" + childSpan + "|" + childParent);
          SpanContext restored = Span.current().getSpanContext();
          System.out.println("SDK_RESTORED|" + restored.getTraceId() + "|" + restored.getSpanId() + "|-");
        } finally {
          parent.end();
        }
        PROVIDER.forceFlush().join(10, TimeUnit.SECONDS);
        for (SpanData span : EXPORTER.getFinishedSpanItems()) {
          System.out.println("SDK_EXPORT|" + span.getName() + "|" + span.getTraceId() + "|" + span.getSpanId() + "|" + span.getParentSpanId());
        }
        System.out.println("DONE");
      } else if (line.equals("CALL_ISOLATED")) {
        Class<?> isolatedSpan = isolatedTarget.getClassLoader().loadClass("io.opentelemetry.api.trace.Span");
        Class<?> systemSpan = Class.forName("io.opentelemetry.api.trace.Span");
        System.out.println("ISOLATED_API_SEPARATE|" + (isolatedSpan != systemSpan));
        ClassLoader previousLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(isolatedTarget.getClassLoader());
        try {
          System.out.print(isolatedTarget.getMethod("run").invoke(null));
        } finally {
          Thread.currentThread().setContextClassLoader(previousLoader);
        }
        System.out.println("ISOLATED_DONE");
      } else if (line.equals("CALL_UNSAMPLED")) {
        EXPORTER.reset();
        SdkTracerProvider offProvider = SdkTracerProvider.builder().setSampler(Sampler.alwaysOff()).build();
        Span offParent = offProvider.get("obi-unsampled-test").spanBuilder("unsampled-parent").startSpan();
        String offTrace = offParent.getSpanContext().getTraceId();
        String offSpan = offParent.getSpanContext().getSpanId();
        try (Scope ignored = offParent.makeCurrent()) {
          System.out.println("UNSAMPLED_RESULT=" + work(11));
          System.out.println("UNSAMPLED_PARENT|" + offTrace + "|" + offSpan + "|0000000000000000");
          System.out.println("UNSAMPLED_CHILD|" + childTrace + "|" + childSpan + "|" + childParent);
        } finally {
          offParent.end();
        }
        offProvider.close();
        PROVIDER.forceFlush().join(10, TimeUnit.SECONDS);
        System.out.println("SDK_EXPORT_COUNT|" + EXPORTER.getFinishedSpanItems().size());
        System.out.println("UNSAMPLED_DONE");
      }
    }
    PROVIDER.close();
  }
}
`

const isolatedSDKTargetSource = `
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.util.concurrent.TimeUnit;

public class IsolatedSdkTarget {
  private static final InMemorySpanExporter EXPORTER = InMemorySpanExporter.create();
  private static final SdkTracerProvider PROVIDER = SdkTracerProvider.builder()
      .addSpanProcessor(SimpleSpanProcessor.create(EXPORTER)).build();
  private static final Tracer TRACER;
  private static String parentTrace;
  private static String parentSpan;
  private static String childTrace;
  private static String childSpan;
  private static String childParent;
  private static String restoredTrace;
  private static String restoredSpan;
  private static String exceptionRestoredTrace;
  private static String exceptionRestoredSpan;

  static {
    OpenTelemetrySdk.builder().setTracerProvider(PROVIDER).build();
    TRACER = PROVIDER.get("obi-isolated-classloader-test");
  }

  public static int work(int value) {
    SpanContext currentContext = Span.current().getSpanContext();
    Span child = TRACER.spanBuilder("isolated-sdk-child").startSpan();
    SpanContext childContext = child.getSpanContext();
    childTrace = childContext.getTraceId();
    childSpan = childContext.getSpanId();
    childParent = currentContext.getSpanId();
    child.end();
    return value + 1;
  }

  public static int workThrows() {
    throw new IllegalStateException("expected child-loader target failure");
  }

  public static String run() throws Exception {
    EXPORTER.reset();
    Span parent = TRACER.spanBuilder("isolated-manual-parent").startSpan();
    SpanContext parentContext = parent.getSpanContext();
    parentTrace = parentContext.getTraceId();
    parentSpan = parentContext.getSpanId();
    try (Scope ignored = parent.makeCurrent()) {
      if (work(17) != 18) throw new AssertionError("isolated target result mismatch");
      SpanContext restored = Span.current().getSpanContext();
      restoredTrace = restored.getTraceId();
      restoredSpan = restored.getSpanId();
      try {
        workThrows();
        throw new AssertionError("expected isolated target exception");
      } catch (IllegalStateException expected) {
        SpanContext restoredAfterException = Span.current().getSpanContext();
        exceptionRestoredTrace = restoredAfterException.getTraceId();
        exceptionRestoredSpan = restoredAfterException.getSpanId();
      }
    } finally {
      parent.end();
    }
    PROVIDER.forceFlush().join(10, TimeUnit.SECONDS);
    StringBuilder output = new StringBuilder();
    output.append("ISOLATED_PARENT|").append(parentTrace).append('|').append(parentSpan).append("|0000000000000000\n");
    output.append("ISOLATED_CHILD|").append(childTrace).append('|').append(childSpan).append('|').append(childParent).append('\n');
    output.append("ISOLATED_RESTORED|").append(restoredTrace).append('|').append(restoredSpan).append("|-\n");
    output.append("ISOLATED_EXCEPTION_RESTORED|").append(exceptionRestoredTrace).append('|').append(exceptionRestoredSpan).append("|-\n");
    for (SpanData span : EXPORTER.getFinishedSpanItems()) {
      output.append("ISOLATED_EXPORT|").append(span.getName()).append('|').append(span.getTraceId()).append('|')
          .append(span.getSpanId()).append('|').append(span.getParentSpanId()).append('\n');
    }
    PROVIDER.close();
    return output.toString();
  }
}
`
