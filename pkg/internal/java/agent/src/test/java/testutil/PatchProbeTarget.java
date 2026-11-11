/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package testutil;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Drives agent ops 4, 5 and 3 over the real control socket, then checks the patched method. */
public final class PatchProbeTarget {
  private static final String OWNER = "testutil.PatchProbeTarget";
  private static final String STRING_DESCRIPTOR = "(Ljava/lang/String;)Ljava/lang/String;";
  private static final byte[] SESSION = new byte[16];
  private static int port;
  private static byte[] token;

  public static void main(String[] args) throws Exception {
    Class<?> control = Class.forName("io.opentelemetry.obi.java.dynamic.DynamicControl");
    Object controller = field(control, "instance").get(null);
    check(controller != null, "agent control not started");
    port = ((ServerSocket) field(control, "server").get(controller)).getLocalPort();
    token = (byte[]) field(control, "token").get(controller);
    SESSION[0] = 7;

    check(exchange(SESSION, 4, null) == null, "claim failed");
    check(lookup("a").equals("original:a"), "baseline changed");

    check(patch(SESSION, "lookup", STRING_DESCRIPTOR, "patched", 60_000, 1) == null, "patch");
    check(lookup("a").equals("patched"), "patch not active: " + lookup("a"));
    check(lookup("a", 1).equals("original2:a"), "other descriptor was patched");
    check(
        concurrentLookups().equals(Arrays.asList("patched", "patched", "patched", "patched")),
        "mt");

    check(exchange(SESSION, 3, out -> out.writeLong(1)) == null, "detach");
    check(lookup("a").equals("original:a"), "detach did not restore the method");

    check(patch(SESSION, "lookup", STRING_DESCRIPTOR, "patched", 1_500, 2) == null, "ttl patch");
    check(lookup("a").equals("patched"), "ttl patch not active");
    Thread.sleep(2_500);
    check(lookup("a").equals("original:a"), "patch outlived its TTL");

    check(patch(SESSION, "lookup", "(Ljava/lang/String;)I", "x", 60_000, 3) != null, "non-String");
    check(patch(SESSION, "lookup", STRING_DESCRIPTOR, "x", -1, 4) != null, "past expiry accepted");
    check(patch(SESSION, "missing", STRING_DESCRIPTOR, "x", 60_000, 5) != null, "unknown method");
    byte[] other = new byte[16];
    check(patch(other, "lookup", STRING_DESCRIPTOR, "x", 60_000, 6) != null, "foreign session");
    check(lookup("a").equals("original:a"), "rejected patch changed behavior");

    System.out.println("PATCH_OK");
  }

  public static String lookup(String key) {
    return "original:" + key;
  }

  public static String lookup(String key, int ignored) {
    return "original2:" + key;
  }

  private static List<String> concurrentLookups() throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(4);
    try {
      List<Future<String>> calls = new ArrayList<>();
      for (int i = 0; i < 4; i++) {
        Callable<String> call = () -> lookup("a");
        calls.add(pool.submit(call));
      }
      List<String> results = new ArrayList<>();
      for (Future<String> call : calls) {
        results.add(call.get());
      }
      return results;
    } finally {
      pool.shutdown();
    }
  }

  private interface Body {
    void write(DataOutputStream out) throws Exception;
  }

  private static String patch(
      byte[] session, String method, String descriptor, String value, long ttlMillis, long cookie)
      throws Exception {
    return exchange(
        session,
        5,
        out -> {
          writeString(out, OWNER);
          writeString(out, method);
          writeString(out, descriptor);
          out.writeByte(1);
          writeString(out, value);
          out.writeLong(System.currentTimeMillis() + ttlMillis);
          out.writeLong(cookie);
          out.writeByte(0);
          writeString(out, "");
          writeString(out, "");
          writeString(out, "");
          out.writeByte(0); // enforce
          out.writeInt(-1); // no predicate
          writeString(out, "");
        });
  }

  /** Returns null on success, or the agent's error message. */
  private static String exchange(byte[] session, int operation, Body body) throws Exception {
    try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
      socket.setSoTimeout(10_000);
      DataOutputStream out = new DataOutputStream(socket.getOutputStream());
      out.write(token);
      out.write(session);
      out.writeByte(operation);
      try {
        if (body != null) {
          body.write(out);
        }
        out.flush();
      } catch (java.net.SocketException refusedEarly) {
        // The agent may answer and close before it has read the whole payload; the reply is
        // still readable below.
      }
      DataInputStream in = new DataInputStream(socket.getInputStream());
      if (in.readUnsignedByte() == 0) {
        if (operation == 5) {
          for (int i = 0; i < 3; i++) {
            in.readFully(new byte[in.readInt()]);
          }
        }
        return null;
      }
      byte[] message = new byte[in.readInt()];
      in.readFully(message);
      return new String(message, StandardCharsets.UTF_8);
    }
  }

  private static void writeString(DataOutputStream out, String value) throws Exception {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    out.writeInt(bytes.length);
    out.write(bytes);
  }

  private static Field field(Class<?> type, String name) throws Exception {
    Field field = type.getDeclaredField(name);
    field.setAccessible(true);
    return field;
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}
