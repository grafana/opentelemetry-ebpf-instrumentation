/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import java.lang.reflect.Method;

/** Uses the application's API (or the Java agent's relocated API), without bundling another SDK. */
public final class SpanContextBridge {
  private final Method current;
  private final Method context;
  private final Method valid;
  private final Method traceId;
  private final Method spanId;
  private final Method flags;
  private final Method flagsByte;
  private final Method state;
  private final Method defaultState;
  private final Method createFlags;
  private final Method createContext;
  private final Method wrap;
  private final Method makeCurrent;
  private final Method close;

  public SpanContextBridge(ClassLoader loader, String prefix) throws ReflectiveOperationException {
    Class<?> span = Class.forName(prefix + ".api.trace.Span", true, loader);
    Class<?> spanContext = Class.forName(prefix + ".api.trace.SpanContext", true, loader);
    Class<?> traceFlags = Class.forName(prefix + ".api.trace.TraceFlags", true, loader);
    Class<?> traceState = Class.forName(prefix + ".api.trace.TraceState", true, loader);
    Class<?> scope = Class.forName(prefix + ".context.Scope", true, loader);
    current = span.getMethod("current");
    context = span.getMethod("getSpanContext");
    valid = spanContext.getMethod("isValid");
    traceId = spanContext.getMethod("getTraceId");
    spanId = spanContext.getMethod("getSpanId");
    flags = spanContext.getMethod("getTraceFlags");
    flagsByte = traceFlags.getMethod("asByte");
    state = spanContext.getMethod("getTraceState");
    defaultState = traceState.getMethod("getDefault");
    createFlags = traceFlags.getMethod("fromByte", byte.class);
    createContext =
        spanContext.getMethod("create", String.class, String.class, traceFlags, traceState);
    wrap = span.getMethod("wrap", spanContext);
    makeCurrent = span.getMethod("makeCurrent");
    close = scope.getMethod("close");
  }

  public Object parent(byte[] ids) throws ReflectiveOperationException {
    Object parent = context.invoke(current.invoke(null));
    if (!(Boolean) valid.invoke(parent)) {
      return null;
    }
    decode((String) traceId.invoke(parent), ids, 0);
    decode((String) spanId.invoke(parent), ids, 16);
    ids[32] = (Byte) flagsByte.invoke(flags.invoke(parent));
    return state.invoke(parent);
  }

  public Object enter(byte[] ids, Object traceState) throws ReflectiveOperationException {
    Object sc =
        createContext.invoke(
            null,
            hex(ids, 0, 16),
            hex(ids, 24, 8),
            createFlags.invoke(null, ids[32]),
            traceState == null ? defaultState.invoke(null) : traceState);
    return makeCurrent.invoke(wrap.invoke(null, sc));
  }

  public void exit(Object scope) throws ReflectiveOperationException {
    close.invoke(scope);
  }

  private static void decode(String hex, byte[] out, int offset) {
    for (int i = 0; i < hex.length() / 2; i++) {
      out[offset + i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
  }

  private static String hex(byte[] bytes, int offset, int length) {
    char[] out = new char[length * 2];
    char[] digits = "0123456789abcdef".toCharArray();
    for (int i = 0; i < length; i++) {
      int value = bytes[offset + i] & 0xff;
      out[i * 2] = digits[value >>> 4];
      out[i * 2 + 1] = digits[value & 15];
    }
    return new String(out);
  }
}
