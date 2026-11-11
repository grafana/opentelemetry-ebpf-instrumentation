/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package testutil;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Drives op 5 with identity assertions over the real control socket. The same class is loaded from
 * two jars by two loaders (same bytecode, different artifact hash), so every refusal reason and the
 * "only the selected loader is patched" rule are checked against a real agent.
 */
public final class PatchIdentityProbeTarget {
  private static final String TARGET = "testutil.IdentityTarget";
  private static final String STRING = "(Ljava/lang/String;)Ljava/lang/String;";
  private static final byte[] SESSION = new byte[16];
  private static int port;
  private static byte[] token;

  /** A loaded-from-a-directory class, to exercise "no plain jar to hash". */
  public static String describe(String key) {
    return "describe:" + key;
  }

  public static void main(String[] args) throws Exception {
    Class<?> control = Class.forName("io.opentelemetry.obi.java.dynamic.DynamicControl");
    Object controller = field(control, "instance").get(null);
    port = ((ServerSocket) field(control, "server").get(controller)).getLocalPort();
    token = (byte[]) field(control, "token").get(controller);
    SESSION[0] = 9;
    check(call(4, null).error == null, "claim failed");

    File dir = Files.createTempDirectory("identity").toFile();
    byte[] bytes = readClass(TARGET);
    File jarA = jar(dir, "a.jar", bytes, null);
    File jarB = jar(dir, "b.jar", bytes, "META-INF/different");
    String shaA = sha256(jarA);
    String shaB = sha256(jarB);
    check(!shaA.equals(shaB), "fixture jars must differ");
    ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
    Class<?> classA =
        new URLClassLoader(new URL[] {jarA.toURI().toURL()}, parent).loadClass(TARGET);
    Class<?> classB =
        new URLClassLoader(new URL[] {jarB.toURI().toURL()}, parent).loadClass(TARGET);
    check(classA != classB && classA.getClassLoader() != classB.getClassLoader(), "two loaders");
    check(lookup(classA).equals("original:k") && lookup(classB).equals("original:k"), "baseline");

    // Two loaders, nothing selected: refuse, and say which loaders to choose from.
    Reply ambiguous = patch(TARGET, "lookup", STRING, "x", 1, false, "", "", "");
    refused(ambiguous, "AMBIGUOUS_LOADER");
    String selectorA = selectorFor(ambiguous.error, shaA);
    String selectorB = selectorFor(ambiguous.error, shaB);
    check(!selectorA.equals(selectorB), "candidate selectors must differ");
    check(lookup(classA).equals("original:k") && lookup(classB).equals("original:k"), "ambiguous");

    refused(
        patch(TARGET, "lookup", STRING, "x", 2, false, "loader:99999", "", ""), "LOADER_MISMATCH");
    refused(
        patch(TARGET, "lookup", STRING, "x", 3, false, selectorA, shaB, ""),
        "ARTIFACT_HASH_MISMATCH");
    refused(
        patch(TARGET, "lookup", STRING, "x", 4, false, selectorA, shaA, zeros()),
        "BYTECODE_FINGERPRINT_MISMATCH");
    refused(patch(TARGET, "missing", STRING, "x", 5, false, selectorA, "", ""), "NO_EXACT_METHOD");
    refused(
        patch(TARGET, "lookup", "(I)Ljava/lang/String;", "x", 5, false, selectorA, "", ""),
        "NO_EXACT_METHOD");
    refused(
        patch("testutil.NoSuchTarget", "lookup", STRING, "x", 6, false, "", "", ""),
        "TARGET_NOT_LOADED");
    refused(
        patch("java.lang.System", "getProperty", STRING, "x", 7, false, "", "", ""),
        "TARGET_NOT_MODIFIABLE");
    check(lookup(classA).equals("original:k") && lookup(classB).equals("original:k"), "refused");

    // Strict mode on a single-loader class: every missing assertion has its own reason.
    String self = PatchIdentityProbeTarget.class.getName();
    refused(patch(self, "describe", STRING, "x", 8, true, "", "", ""), "MISSING_ARTIFACT_HASH");
    refused(patch(self, "describe", STRING, "x", 8, true, "", shaA, ""), "MISSING_FINGERPRINT");
    refused(
        patch(self, "describe", STRING, "x", 8, true, "", shaA, zeros()),
        "MISSING_LOADER_SELECTOR");
    // Loaded from a directory: there is no jar to hash, so an asserted hash is refused.
    refused(
        patch(self, "describe", STRING, "x", 9, false, "", shaA, ""),
        "ARTIFACT_IDENTITY_UNAVAILABLE");
    check(describe("k").equals("describe:k"), "refused patch changed the fixture");
    Reply unasserted = patch(self, "describe", STRING, "patched-self", 10, false, "", "", "");
    check(unasserted.error == null, "unasserted patch on a directory class: " + unasserted.error);
    check(unasserted.artifact.isEmpty(), "no artifact evidence for a directory");
    check(unasserted.fingerprint.length() == 64, "fingerprint evidence expected");
    check(describe("k").equals("patched-self"), "unasserted patch not active");
    check(call(3, out -> out.writeLong(10)).error == null, "detach self");
    check(describe("k").equals("describe:k"), "detach self did not restore");

    // Select loader A only: B (same name, same bytecode) stays unpatched.
    Reply a = patch(TARGET, "lookup", STRING, "patched-A", 20, false, selectorA, shaA, "");
    check(a.error == null, "patch A: " + a.error);
    check(a.loader.equals(selectorA) && a.artifact.equals(shaA), "evidence A: " + a);
    check(a.fingerprint.length() == 64, "fingerprint evidence A");
    check(lookup(classA).equals("patched-A"), "A not patched: " + lookup(classA));
    check(lookup(classB).equals("original:k"), "B was patched");
    check(lookup2(classA).equals("original2:k"), "other overload of A was patched");

    // Asserting the fingerprint and artifact that A reported is accepted for B (same bytecode,
    // different jar), and the two loaders then carry independent patches.
    Reply b =
        patch(TARGET, "lookup", STRING, "patched-B", 21, true, selectorB, shaB, a.fingerprint);
    check(b.error == null, "patch B: " + b.error);
    check(b.fingerprint.equals(a.fingerprint), "same bytecode, same fingerprint");
    check(lookup(classA).equals("patched-A") && lookup(classB).equals("patched-B"), "independent");

    // Detaching A's cookie leaves B alone, and a stale cookie removes nothing.
    check(call(3, out -> out.writeLong(20)).error == null, "detach A");
    check(lookup(classA).equals("original:k"), "A not restored");
    check(lookup(classB).equals("patched-B"), "detaching A removed B's patch");
    check(call(3, out -> out.writeLong(20)).error == null, "stale detach");
    check(lookup(classB).equals("patched-B"), "stale cookie removed B's patch");
    check(call(3, out -> out.writeLong(21)).error == null, "detach B");
    check(lookup(classB).equals("original:k"), "B not restored");
    System.out.println("IDENTITY_OK");
  }

  private static final class Reply {
    String error;
    String loader = "";
    String artifact = "";
    String fingerprint = "";

    @Override
    public String toString() {
      return "loader=" + loader + " artifact=" + artifact + " fingerprint=" + fingerprint;
    }
  }

  private interface Body {
    void write(DataOutputStream out) throws Exception;
  }

  private static Reply patch(
      String className,
      String method,
      String descriptor,
      String value,
      long cookie,
      boolean strict,
      String loader,
      String artifact,
      String fingerprint)
      throws Exception {
    return call(
        5,
        out -> {
          writeString(out, className);
          writeString(out, method);
          writeString(out, descriptor);
          out.writeByte(1);
          writeString(out, value);
          out.writeLong(System.currentTimeMillis() + 60_000);
          out.writeLong(cookie);
          out.writeByte(strict ? 1 : 0);
          writeString(out, loader);
          writeString(out, artifact);
          writeString(out, fingerprint);
          out.writeByte(0); // enforce
          out.writeInt(-1); // no predicate
          writeString(out, "");
        });
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
        reply.error = readString(in);
        return reply;
      }
      if (operation == 5) {
        reply.loader = readString(in);
        reply.artifact = readString(in);
        reply.fingerprint = readString(in);
      }
      return reply;
    }
  }

  private static void refused(Reply reply, String reason) {
    check(reply.error != null, "expected refusal " + reason);
    check(reply.error.startsWith("PatchRefusal " + reason + ": "), reason + " but: " + reply.error);
  }

  private static String selectorFor(String message, String artifactSha) {
    Matcher matcher =
        Pattern.compile("(loader:\\d+) \\([^,]*, artifact_sha256=" + artifactSha + "\\)")
            .matcher(message);
    check(matcher.find(), "no candidate for " + artifactSha + " in: " + message);
    return matcher.group(1);
  }

  private static String lookup(Class<?> type) throws Exception {
    Method method = type.getMethod("lookup", String.class);
    return (String) method.invoke(type.getConstructor().newInstance(), "k");
  }

  private static String lookup2(Class<?> type) throws Exception {
    Method method = type.getMethod("lookup", String.class, int.class);
    return (String) method.invoke(type.getConstructor().newInstance(), "k", 1);
  }

  private static byte[] readClass(String name) throws Exception {
    try (InputStream in =
        PatchIdentityProbeTarget.class
            .getClassLoader()
            .getResourceAsStream(name.replace('.', '/') + ".class")) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int read;
      while ((read = in.read(buffer)) >= 0) {
        out.write(buffer, 0, read);
      }
      return out.toByteArray();
    }
  }

  private static File jar(File dir, String name, byte[] classBytes, String extraEntry)
      throws Exception {
    File file = new File(dir, name);
    try (JarOutputStream out = new JarOutputStream(new FileOutputStream(file))) {
      out.putNextEntry(new JarEntry(TARGET.replace('.', '/') + ".class"));
      out.write(classBytes);
      out.closeEntry();
      if (extraEntry != null) {
        out.putNextEntry(new JarEntry(extraEntry));
        out.write(1);
        out.closeEntry();
      }
    }
    return file;
  }

  private static String sha256(File file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    StringBuilder hex = new StringBuilder();
    for (byte b : digest.digest(Files.readAllBytes(file.toPath()))) {
      hex.append(String.format("%02x", b & 255));
    }
    return hex.toString();
  }

  private static String zeros() {
    return new String(new char[64]).replace('\0', '0');
  }

  private static String readString(DataInputStream in) throws Exception {
    byte[] bytes = new byte[in.readInt()];
    in.readFully(bytes);
    return new String(bytes, StandardCharsets.UTF_8);
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
