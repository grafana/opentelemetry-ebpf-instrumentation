/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package testutil;

import static java.util.concurrent.TimeUnit.SECONDS;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Isolated fixture for taskWrapping propagation from a selected dynamic method. */
public final class AsyncDynamicProbeTarget {
  private static final InMemorySpanExporter EXPORTER = InMemorySpanExporter.create();
  private static final SdkTracerProvider PROVIDER =
      SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(EXPORTER)).build();
  private static final Tracer TRACER = PROVIDER.get("dynamic-async-test");
  private static final ExecutorService WORKER = Executors.newSingleThreadExecutor();
  private static final Executor CONTEXTUAL_WORKER = Context.taskWrapping(WORKER);

  public static void main(String[] args) throws Exception {
    Class<?> control = Class.forName("io.opentelemetry.obi.java.dynamic.DynamicControl");
    Object instance = field(control, "instance").get(null);
    Object instrumentation = field(control, "instrumentation").get(instance);
    Method attach = instrumentation.getClass().getMethod("attach", String.class, long.class);
    Method detach = instrumentation.getClass().getMethod("detach", long.class);
    attach.invoke(instrumentation, AsyncDynamicProbeTarget.class.getName() + ".asyncWork", 501L);

    Span server = TRACER.spanBuilder("server").startSpan();
    String serverId = server.getSpanContext().getSpanId();
    try (Scope ignored = server.makeCurrent()) {
      asyncWork();
      check(
          Span.current().getSpanContext().getSpanId().equals(serverId),
          "dynamic scope leaked back to submitting thread");
      Future<Boolean> reusedWorker =
          WORKER.submit(() -> !Span.current().getSpanContext().isValid());
      check(reusedWorker.get(10, SECONDS), "reused worker retained task-wrapped context");
    } finally {
      server.end();
      detach.invoke(instrumentation, 501L);
      WORKER.shutdownNow();
      check(WORKER.awaitTermination(10, SECONDS), "worker did not terminate before exporter close");
    }

    try {
      check(PROVIDER.forceFlush().join(10, SECONDS).isSuccess(), "provider flush failed");
      List<SpanData> spans = EXPORTER.getFinishedSpanItems();
      check(spans.size() == 2, "unexpected SDK spans: " + spans.size());
      SpanData child = null;
      for (SpanData span : spans) {
        if (span.getName().equals("async-child")) {
          child = span;
          break;
        }
      }
      check(child != null, "async SDK child was not exported");
      check(child.getParentSpanId().equals(lastDynamicParent), "async child parent mismatch");
      check(child.getTraceId().equals(lastDynamicTrace), "async child trace mismatch");
      System.out.println("ASYNC_DYNAMIC_OK");
    } finally {
      PROVIDER.close();
    }
  }

  private static volatile String lastDynamicParent;
  private static volatile String lastDynamicTrace;

  public static void asyncWork() throws Exception {
    SpanContext dynamicParent = Span.current().getSpanContext();
    lastDynamicParent = dynamicParent.getSpanId();
    lastDynamicTrace = dynamicParent.getTraceId();
    CompletableFuture<Void> completed = new CompletableFuture<>();
    CONTEXTUAL_WORKER.execute(
        () -> {
          Span child = TRACER.spanBuilder("async-child").startSpan();
          child.end();
          completed.complete(null);
        });
    completed.get(10, SECONDS);
  }

  private static Field field(Class<?> type, String name) throws Exception {
    Field field = type.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }
}
