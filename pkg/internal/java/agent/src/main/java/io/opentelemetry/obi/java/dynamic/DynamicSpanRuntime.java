/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.DynamicSpanPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Bootstrap-visible advice runtime. It deliberately has no Byte Buddy or SDK dependency. */
public final class DynamicSpanRuntime {
  private static final ConcurrentHashMap<String, Long> PROBES = new ConcurrentHashMap<>();
  private static final ThreadLocal<Boolean> BUSY = new ThreadLocal<>();
  private static final ThreadLocal<Invocation> CURRENT = new ThreadLocal<>();
  private static final ThreadLocal<NativeMemory> PACKET = new ThreadLocal<>();
  private static final AtomicLong SEQUENCE = new AtomicLong();
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final ClassValue<SpanContextBridge[]> BRIDGES =
      new ClassValue<SpanContextBridge[]>() {
        @Override
        protected SpanContextBridge[] computeValue(Class<?> type) {
          SpanContextBridge application = null;
          SpanContextBridge agent = null;
          try {
            application = new SpanContextBridge(type.getClassLoader(), "io.opentelemetry");
          } catch (Throwable ignored) {
          }
          try {
            agent =
                new SpanContextBridge(null, "io.opentelemetry.javaagent.shaded.io.opentelemetry");
          } catch (Throwable ignored) {
          }
          return new SpanContextBridge[] {application, agent};
        }
      };

  private DynamicSpanRuntime() {}

  public static void add(String method, long cookie) {
    PROBES.put(method, cookie);
  }

  public static void remove(String method, long cookie) {
    PROBES.remove(method, cookie);
  }

  public static Invocation enter(
      Class<?> owner, String method, Object[] arguments, boolean returns) {
    if (Boolean.TRUE.equals(BUSY.get())) {
      return null;
    }
    Long cookie = PROBES.get(owner.getName() + "." + method);
    if (cookie == null) {
      return null;
    }
    BUSY.set(true);
    Invocation call = new Invocation(cookie, SEQUENCE.incrementAndGet(), CURRENT.get(), returns);
    try {
      if (call.previous != null) {
        System.arraycopy(call.previous.ids, 0, call.ids, 0, 16);
        System.arraycopy(call.previous.ids, 24, call.ids, 16, 8);
        call.ids[32] = call.previous.ids[32];
      }
      Object state = null;
      for (SpanContextBridge bridge : BRIDGES.get(owner)) {
        if (bridge == null) {
          continue;
        }
        Object candidate;
        try {
          candidate = bridge.parent(call.ids);
        } catch (ReflectiveOperationException unavailable) {
          continue;
        }
        if (call.bridge == null) {
          call.bridge = bridge;
        }
        if (candidate != null) {
          call.bridge = bridge;
          state = candidate;
          break;
        }
      }
      byte[] random = new byte[24];
      RANDOM.nextBytes(random);
      System.arraycopy(random, 16, call.ids, 24, 8);
      if (empty(call.ids, 0, 16)) {
        System.arraycopy(random, 0, call.ids, 0, 16);
        call.ids[32] = 1;
        call.root = true;
      }
      String[] values = new String[Math.min(arguments.length, DynamicSpanPacket.MAX_ARGS)];
      for (int i = 0; i < values.length; i++) {
        values[i] = stringify(arguments[i]);
      }
      NativeMemory packet = packet();
      DynamicSpanPacket.write(
          packet,
          OperationType.DYNAMIC_SPAN_START.code,
          cookie,
          call.id,
          Thread.currentThread().getId(),
          call.ids,
          values);
      // An absent SDK parent lets BPF adopt OBI's active server context.
      packet.setByte(3, (byte) (call.root ? 1 : 0));
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
      DynamicSpanPacket.readContext(packet, call.ids);
      if (call.bridge != null) {
        try {
          call.scope = call.bridge.enter(call.ids, state);
        } catch (ReflectiveOperationException unavailable) {
          // Keep the timing span if a nonstandard SDK cannot accept the scope.
        }
      }
      CURRENT.set(call);
      return call;
    } catch (Throwable ignored) {
      closeScope(call);
      return null;
    } finally {
      BUSY.remove();
    }
  }

  public static void exit(Invocation call, Object result, Throwable error) {
    if (call == null) {
      return;
    }
    BUSY.set(true);
    try {
      String[] values =
          new String[] {
            call.returns && error == null ? stringify(result) : null,
            error == null ? null : stringify(error)
          };
      NativeMemory packet = packet();
      DynamicSpanPacket.write(
          packet,
          OperationType.DYNAMIC_SPAN_END.code,
          call.cookie,
          call.id,
          Thread.currentThread().getId(),
          call.ids,
          values);
      if (call.previous != null) {
        packet.setLong(64, call.previous.cookie);
        packet.write(72, call.previous.ids, 0, call.previous.ids.length);
      }
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    } catch (Throwable ignored) {
    } finally {
      closeScope(call);
      if (call.previous == null) {
        CURRENT.remove();
      } else {
        CURRENT.set(call.previous);
      }
      BUSY.remove();
    }
  }

  private static NativeMemory packet() {
    NativeMemory packet = PACKET.get();
    if (packet == null) {
      packet = new NativeMemory(DynamicSpanPacket.PACKET_SIZE);
      PACKET.set(packet);
    }
    return packet;
  }

  private static boolean empty(byte[] bytes, int offset, int length) {
    for (int i = offset; i < offset + length; i++) {
      if (bytes[i] != 0) {
        return false;
      }
    }
    return true;
  }

  private static void closeScope(Invocation call) {
    if (call.scope != null) {
      try {
        call.bridge.exit(call.scope);
      } catch (Throwable ignored) {
      }
    }
  }

  public static String stringify(Object value) {
    try {
      String result = String.valueOf(value);
      if (result == null) {
        return "null";
      }
      return result.substring(0, Math.min(result.length(), DynamicSpanPacket.STRING_SIZE - 1));
    } catch (Throwable error) {
      return "<toString failed>";
    }
  }

  public static final class Invocation {
    final long cookie;
    final long id;
    final Invocation previous;
    final boolean returns;
    final byte[] ids = new byte[33];
    boolean root;
    SpanContextBridge bridge;
    Object scope;

    Invocation(long cookie, long id, Invocation previous, boolean returns) {
      this.cookie = cookie;
      this.id = id;
      this.previous = previous;
      this.returns = returns;
    }
  }
}
