/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package testutil;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/** Exercises the agent's bootstrap API with no application SDK in the context path. */
public final class AgentDynamicProbeTarget {
  private static final String API = "io.opentelemetry.javaagent.shaded.io.opentelemetry";
  private static Class<?> span;
  private static Class<?> spanContext;
  private static Object tracer;
  private static String serverID;
  private static String traceID;
  private static String annotationID;
  private static boolean attached;

  public static void main(String[] args) throws Exception {
    span = Class.forName(API + ".api.trace.Span", true, null);
    spanContext = Class.forName(API + ".api.trace.SpanContext", true, null);
    tracer =
        Class.forName(API + ".api.GlobalOpenTelemetry", true, null)
            .getMethod("getTracer", String.class)
            .invoke(null, "dynamic-agent-test");
    Class<?> control = Class.forName("io.opentelemetry.obi.java.dynamic.DynamicControl");
    Object instance = field(control, "instance").get(null);
    Object controller = field(control, "instrumentation").get(instance);
    controller
        .getClass()
        .getMethod("attach", String.class, long.class)
        .invoke(controller, "testutil.AgentDynamicProbeTarget.work", 101L);
    Object server = start("server");
    Object serverContext = span.getMethod("getSpanContext").invoke(server);
    serverID = id(serverContext, "getSpanId");
    traceID = id(serverContext, "getTraceId");
    Object scope = span.getMethod("makeCurrent").invoke(server);
    try {
      attached = true;
      annotatedWork();
      check(id(current(), "getSpanId").equals(serverID), "SDK scope not restored");
      controller.getClass().getMethod("detach", long.class).invoke(controller, 101L);
      attached = false;
      work();
    } finally {
      attached = false;
      controller.getClass().getMethod("detach", long.class).invoke(controller, 101L);
      Class.forName(API + ".context.Scope", true, null).getMethod("close").invoke(scope);
      span.getMethod("end").invoke(server);
    }
    System.out.println("DYNAMIC_OK");
  }

  @WithSpan("annotated-parent")
  public static void annotatedWork() throws Exception {
    annotationID = id(current(), "getSpanId");
    check(!annotationID.equals(serverID), "@WithSpan did not create an agent span");
    check(id(current(), "getTraceId").equals(traceID), "annotation span lost server trace");
    work();
    check(
        id(current(), "getSpanId").equals(annotationID),
        "dynamic scope did not restore annotation span");
  }

  public static void work() throws Exception {
    String dynamicID = id(current(), "getSpanId");
    check(id(current(), "getTraceId").equals(traceID), "custom span lost agent trace");
    check(attached != dynamicID.equals(serverID), "incorrect method scope");
    if (annotationID != null && attached) {
      check(!dynamicID.equals(annotationID), "dynamic span replaced annotation parent");
    }
    Object child = start("client");
    Method parent = child.getClass().getMethod("getParentSpanContext");
    parent.setAccessible(true);
    check(id(parent.invoke(child), "getSpanId").equals(dynamicID), "SDK client parent mismatch");
    span.getMethod("end").invoke(child);
  }

  private static Object start(String name) throws Exception {
    Object builder =
        Class.forName(API + ".api.trace.Tracer", true, null)
            .getMethod("spanBuilder", String.class)
            .invoke(tracer, name);
    return Class.forName(API + ".api.trace.SpanBuilder", true, null)
        .getMethod("startSpan")
        .invoke(builder);
  }

  private static Object current() throws Exception {
    return span.getMethod("getSpanContext").invoke(span.getMethod("current").invoke(null));
  }

  private static String id(Object context, String method) throws Exception {
    return (String) spanContext.getMethod(method).invoke(context);
  }

  private static Field field(Class<?> owner, String name) throws Exception {
    Field field = owner.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static void check(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }
}
