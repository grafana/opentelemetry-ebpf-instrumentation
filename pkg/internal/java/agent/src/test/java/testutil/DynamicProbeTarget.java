/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package testutil;

import io.opentelemetry.api.trace.*;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class DynamicProbeTarget {
  private static final InMemorySpanExporter EXPORTER = InMemorySpanExporter.create();
  private static final SdkTracerProvider PROVIDER =
      SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(EXPORTER)).build();
  private static final Tracer TRACER = PROVIDER.get("dynamic-test");
  private static final String PREFIX = "testutil.DynamicProbeTarget.";
  private static String outerId;
  private static String innerId;
  private static String parentId;

  public static void main(String[] args) throws Exception {
    Class<?> control = Class.forName("io.opentelemetry.obi.java.dynamic.DynamicControl");
    Object controller = field(control, "instance").get(null);
    check(controller != null, "agent control not started");
    Object instrumenter = field(control, "instrumentation").get(controller);
    Method attach = instrumenter.getClass().getMethod("attach", String.class, long.class);
    Method detach = instrumenter.getClass().getMethod("detach", long.class);
    @SuppressWarnings("unchecked")
    List<String> symbols =
        (List<String>) instrumenter.getClass().getMethod("symbols").invoke(instrumenter);
    check(symbols.contains(PREFIX + "outer"), "missing method symbol");
    String[] names = {"outer", "inner", "empty", "fail", "object", "recursive", "rootBranch"};
    for (int i = 0; i < names.length; i++) {
      attach.invoke(instrumenter, PREFIX + names[i], (long) i + 1);
    }
    Span server = TRACER.spanBuilder("server").startSpan();
    parentId = server.getSpanContext().getSpanId();
    try (Scope ignored = server.makeCurrent()) {
      check(
          current().equals(parentId),
          "server scope mismatch before dynamic call: " + current() + " / " + parentId);
      check(outer(42, "hello") == 43, "changed return");
      check(current().equals(parentId), "outer scope leaked: " + current() + " / " + parentId);
      ByteBuffer packet = packet();
      check(text(packet, 112).equals("43"), "return value not captured");
      empty();
      check(current().equals(parentId), "void scope leaked");
      try {
        fail();
        throw new AssertionError("exception swallowed");
      } catch (IllegalArgumentException expected) {
        check(current().equals(parentId), "exception scope leaked");
        check(text(packet(), 112 + 128).contains("fixture exception"), "exception not captured");
      }
      Object broken =
          new Object() {
            public String toString() {
              throw new IllegalStateException();
            }
          };
      check(object(broken) == broken, "changed object return");
      check(text(packet(), 112).equals("<toString failed>"), "toString failure escaped");
      check(object(null) == null, "changed null return");
      check(text(packet(), 112).equals("null"), "null not captured");
      check(recursive(3) == 3, "recursion changed result");
      check(current().equals(parentId), "recursive scope leaked");
      rootBranch();
      check(current().equals(parentId), "new-root branch scope leaked");
      for (int i = 0; i < names.length; i++) {
        detach.invoke(instrumenter, (long) i + 1);
      }
      check(outer(42, "hello") == 43, "detach changed return");
      check(outerId.equals(parentId), "deleted method still changes context");
    } finally {
      server.end();
    }
    List<SpanData> spans = EXPORTER.getFinishedSpanItems();
    check(spans.size() == 8, "custom span was also exported through SDK: " + spans.size());
    check(spans.get(0).getName().equals("child"), "SDK child missing");
    check(spans.get(0).getParentSpanId().equals(innerIdBeforeDetach), "SDK child parent mismatch");
    check(
        spans.get(0).getTraceId().equals(server.getSpanContext().getTraceId()),
        "trace ID mismatch");
    PROVIDER.close();
    System.out.println("DYNAMIC_OK");
  }

  private static String innerIdBeforeDetach;

  public static int outer(int value, String text) throws Exception {
    outerId = current();
    if (!outerId.equals(parentId)) {
      check(text(packet(), 112).equals("42"), "scalar arg not captured");
      check(text(packet(), 112 + 128).equals("hello"), "string arg not captured");
    }
    int result = inner(value);
    check(current().equals(outerId), "inner scope leaked");
    return result;
  }

  public static int inner(int value) {
    innerId = current();
    if (innerIdBeforeDetach == null) {
      innerIdBeforeDetach = innerId;
      check(!innerId.equals(outerId), "nested custom span missing");
    }
    Span child = TRACER.spanBuilder("child").startSpan();
    child.end();
    return value + 1;
  }

  public static void empty() {
    check(!current().equals(parentId), "void method not instrumented");
    TRACER.spanBuilder("void-child").startSpan().end();
  }

  public static void fail() {
    check(!current().equals(parentId), "throwing method not instrumented");
    TRACER.spanBuilder("exception-child").startSpan().end();
    throw new IllegalArgumentException("fixture exception");
  }

  public static Object object(Object value) {
    return value;
  }

  public static int recursive(int depth) {
    String prior = current();
    if (depth == 0) return 0;
    int result = recursive(depth - 1) + 1;
    check(current().equals(prior), "recursive scope not restored");
    return result;
  }

  public static void rootBranch() {
    String outer = current();
    Span root = TRACER.spanBuilder("explicit-root").setNoParent().startSpan();
    try (Scope ignored = root.makeCurrent()) {
      inner(4);
      check(
          current().equals(root.getSpanContext().getSpanId()), "explicit root scope not restored");
    } finally {
      root.end();
    }
    check(current().equals(outer), "explicit root replaced dynamic parent");
    TRACER.spanBuilder("after-root").startSpan().end();
  }

  private static String current() {
    return Span.current().getSpanContext().getSpanId();
  }

  private static ByteBuffer packet() throws Exception {
    Class<?> runtime =
        Class.forName("io.opentelemetry.obi.java.dynamic.DynamicSpanRuntime", true, null);
    Object memory = ((ThreadLocal<?>) field(runtime, "PACKET").get(null)).get();
    check(memory != null, "no dynamic packet");
    return (ByteBuffer) memory.getClass().getMethod("getBuffer").invoke(memory);
  }

  private static Field field(Class<?> type, String name) throws Exception {
    Field field = type.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static String text(ByteBuffer packet, int offset) {
    byte[] value = new byte[128];
    int count = 0;
    while (count < value.length && packet.get(offset + count) != 0) {
      value[count] = packet.get(offset + count);
      count++;
    }
    return new String(value, 0, count, StandardCharsets.UTF_8);
  }

  private static void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }
}
