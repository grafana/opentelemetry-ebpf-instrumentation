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
import java.util.HashMap;
import java.util.Map;

/**
 * Drives observe-mode patches over the real control socket (ops 4, 5, 6, 3): calls are counted, the
 * method never changes, and a counter that is not there is unknown, not zero.
 */
public final class PatchObserveProbeTarget {
  private static final String OWNER = "testutil.PatchObserveProbeTarget";
  private static final String LOOKUP = "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;";
  private static final String MIXED = "(Ljava/lang/String;I)Ljava/lang/String;";
  private static final String CANARY = "dns://canary.fleetops.test/x";
  private static final byte[] SESSION = new byte[16];
  private static int port;
  private static byte[] token;

  public static void main(String[] args) throws Exception {
    Class<?> control = Class.forName("io.opentelemetry.obi.java.dynamic.DynamicControl");
    Object controller = field(control, "instance").get(null);
    check(controller != null, "agent control not started");
    port = ((ServerSocket) field(control, "server").get(controller)).getLocalPort();
    token = (byte[]) field(control, "token").get(controller);
    SESSION[0] = 9;
    check(call(4, null).error == null, "claim failed");

    // Unknown is not zero: nothing observes yet, so there is no entry at all.
    check(counters().isEmpty(), "counters before any observe patch");

    // Variant "jar present, method never called": a known zero, with an observation start.
    check(observe(1, 60_000, -1, "").error == null, "observe patch");
    Row row = counters().get(1L);
    check(row != null, "observing patch has no counters entry");
    check(row.calls == 0 && row.firstSeen == 0 && row.lastSeen == 0, "never-called is not zero");
    check(!row.hasPredicate, "no predicate was set");
    check(row.since > 0 && row.now >= row.since, "observation interval missing");

    // Observe mode never changes the call.
    check(lookup("a").equals("original:a"), "observe changed the result");
    check(lookup(CANARY).equals("original:" + CANARY), "observe changed the canary result");
    row = counters().get(1L);
    check(row.calls == 2, "calls " + row.calls);
    check(row.firstSeen > 0 && row.lastSeen >= row.firstSeen, "first/last seen");

    // Predicate: the positive fixture fires before any zero is trusted.
    check(observe(2, 60_000, 1, "canary.fleetops.test").error == null, "predicate patch");
    check(counters().get(1L) == null, "replaced patch still reports counters");
    row = counters().get(2L);
    check(row.hasPredicate && row.calls == 0 && row.hits == 0, "fresh predicate counters");
    lookup(CANARY);
    row = counters().get(2L);
    check(row.calls == 1 && row.hits == 1, "positive fixture did not fire: " + row.hits);

    // Benign only, then canary mixed with benign.
    long hits = row.hits;
    for (int i = 0; i < 5; i++) {
      lookup("benign-" + i);
    }
    row = counters().get(2L);
    check(row.calls == 6 && row.hits == hits, "benign calls counted as hits: " + row.hits);
    lookup(CANARY);
    lookup("b");
    row = counters().get(2L);
    check(row.calls == 8 && row.hits == 2, "mixed: " + row.calls + "/" + row.hits);
    check(lookup(CANARY).equals("original:" + CANARY), "predicate match changed the result");

    // The predicate reads the key argument (index 1) only, never the event (index 0).
    long before = counters().get(2L).hits;
    check(withCanaryAsEvent(CANARY, "plain").equals("original:plain"), "behaviour");
    check(counters().get(2L).hits == before, "the predicate read argument 0");

    // Closed predicate: refuse anything that is not a literal over one String parameter.
    refused(observe(3, 60_000, 0, "x"), "PREDICATE_INVALID", "argument is an Object, not a String");
    refused(observe(3, 60_000, 5, "x"), "PREDICATE_INVALID", "argument out of range");
    refused(observe(3, 60_000, 1, ""), "PREDICATE_INVALID", "index without literal");
    refused(observe(3, 60_000, -1, "x"), "PREDICATE_INVALID", "literal without index");
    refused(observe(3, 60_000, 1, longLiteral()), "PREDICATE_INVALID", "literal too long");
    refused(enforce(3, 1, "x"), "PREDICATE_INVALID", "predicate on an enforcing patch");
    check(counters().get(2L) != null, "a refused patch dropped the live one");

    // An enforcing patch on another method reports no counters and still returns its constant.
    check(enforce(4, -1, "").error == null, "enforce patch");
    check(lookup2(CANARY, 0).equals("patched"), "enforce patch not active");
    check(counters().get(4L) == null, "enforcing patch has counters");

    // Detached: unknown, not zero.
    check(call(3, out -> out.writeLong(2)).error == null, "detach");
    check(counters().get(2L) == null, "detached patch still has counters");
    check(lookup(CANARY).equals("original:" + CANARY), "detach changed behaviour");

    // Expired: unknown again.
    check(observe(5, 1_200, -1, "").error == null, "ttl observe");
    lookup("a");
    check(counters().get(5L).calls == 1, "ttl counters");
    Thread.sleep(2_500);
    check(counters().get(5L) == null, "expired patch still has counters");

    System.out.println("OBSERVE_OK");
  }

  public static String lookup(Object event, String key) {
    return "original:" + key;
  }

  public static String lookup2(String key, int ignored) {
    return "original2:" + key;
  }

  private static String lookup(String key) {
    return lookup(null, key);
  }

  /** Calls the observed method with the canary in argument 0 and a benign key in argument 1. */
  private static String withCanaryAsEvent(String canary, String plain) {
    return lookup(canary, plain);
  }

  private static String longLiteral() {
    StringBuilder text = new StringBuilder();
    for (int i = 0; i < 257; i++) {
      text.append('x');
    }
    return text.toString();
  }

  private static final class Row {
    long now;
    long calls;
    long hits;
    boolean hasPredicate;
    long firstSeen;
    long lastSeen;
    long since;
  }

  private static final class Reply {
    String error;
    Map<Long, Row> rows;
  }

  private interface Body {
    void write(DataOutputStream out) throws Exception;
  }

  private static Reply observe(long cookie, long ttl, int argument, String contains)
      throws Exception {
    return patch("lookup", LOOKUP, "", cookie, ttl, true, argument, contains);
  }

  private static Reply enforce(long cookie, int argument, String contains) throws Exception {
    return patch("lookup2", MIXED, "patched", cookie, 60_000, false, argument, contains);
  }

  private static Reply patch(
      String method,
      String descriptor,
      String value,
      long cookie,
      long ttl,
      boolean observe,
      int argument,
      String contains)
      throws Exception {
    return call(
        5,
        out -> {
          writeString(out, OWNER);
          writeString(out, method);
          writeString(out, descriptor);
          out.writeByte(1);
          writeString(out, value);
          out.writeLong(System.currentTimeMillis() + ttl);
          out.writeLong(cookie);
          out.writeByte(0);
          writeString(out, "");
          writeString(out, "");
          writeString(out, "");
          out.writeByte(observe ? 1 : 0);
          out.writeInt(argument);
          writeString(out, contains);
        });
  }

  private static Map<Long, Row> counters() throws Exception {
    Reply reply = call(6, null);
    check(reply.error == null, "counters: " + reply.error);
    return reply.rows;
  }

  private static Reply call(int operation, Body body) throws Exception {
    try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
      socket.setSoTimeout(30_000);
      DataOutputStream out = new DataOutputStream(socket.getOutputStream());
      out.write(token);
      out.write(SESSION);
      out.writeByte(operation);
      if (body != null) {
        body.write(out);
      }
      out.flush();
      DataInputStream in = new DataInputStream(socket.getInputStream());
      Reply reply = new Reply();
      if (in.readUnsignedByte() != 0) {
        byte[] message = new byte[in.readInt()];
        in.readFully(message);
        reply.error = new String(message, StandardCharsets.UTF_8);
        return reply;
      }
      if (operation == 5) {
        for (int i = 0; i < 3; i++) {
          in.readFully(new byte[in.readInt()]);
        }
      }
      if (operation == 6) {
        long now = in.readLong();
        int count = in.readInt();
        reply.rows = new HashMap<>();
        for (int i = 0; i < count; i++) {
          Row row = new Row();
          row.now = now;
          long cookie = in.readLong();
          row.calls = in.readLong();
          row.hits = in.readLong();
          row.hasPredicate = in.readUnsignedByte() != 0;
          row.firstSeen = in.readLong();
          row.lastSeen = in.readLong();
          row.since = in.readLong();
          reply.rows.put(cookie, row);
        }
      }
      return reply;
    }
  }

  private static void refused(Reply reply, String reason, String what) {
    check(
        reply.error != null && reply.error.contains("PatchRefusal " + reason + ":"),
        what + ": " + reply.error);
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
