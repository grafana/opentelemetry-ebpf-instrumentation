/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import java.io.File;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.net.URI;
import java.nio.file.Files;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;

/**
 * Resolves a patch target to exactly one method in exactly one class loader, or refuses. Every
 * refusal has a distinct {@link PatchRefusal#reason()}. Assertions the patch makes (loader
 * selector, artifact SHA-256, method fingerprint) are verified; the ones it leaves out are not
 * asserted, and whatever could be resolved is returned as evidence.
 */
final class PatchResolver {
  private final Instrumentation inst;
  private final LoaderRegistry loaders = new LoaderRegistry();
  private final MethodFingerprint.Capture capture = new MethodFingerprint.Capture();
  private final Map<String, CachedHash> hashes = new ConcurrentHashMap<>();

  /** Must be constructed before this agent's other transformers so the capture sees clean bytes. */
  PatchResolver(Instrumentation inst) {
    this.inst = inst;
    inst.addTransformer(capture, true);
  }

  String selectorOf(ClassLoader loader) {
    return loaders.selectorOf(loader);
  }

  static final class Resolved {
    final Class<?> type;
    final PatchIdentity.Evidence evidence;

    Resolved(Class<?> type, PatchIdentity.Evidence evidence) {
      this.type = type;
      this.evidence = evidence;
    }
  }

  Resolved resolve(
      String className, String method, String descriptor, PatchIdentity.Request request) {
    if (request.strict) {
      if (request.artifactSha256 == null) {
        throw new PatchRefusal(
            "MISSING_ARTIFACT_HASH", "a strict patch must assert artifact_sha256");
      }
      if (request.fingerprint == null) {
        throw new PatchRefusal("MISSING_FINGERPRINT", "a strict patch must assert fingerprint");
      }
    }
    if (DynamicInstrumentation.excluded(className)) {
      throw new PatchRefusal("TARGET_NOT_MODIFIABLE", className + " is excluded by agent policy");
    }
    List<Class<?>> named = new ArrayList<>();
    List<Class<?>> exact = new ArrayList<>();
    for (Class<?> type : inst.getAllLoadedClasses()) {
      if (type.isArray() || type.isPrimitive() || !type.getName().equals(className)) {
        continue;
      }
      named.add(type);
      if (declares(type, method, descriptor)) {
        exact.add(type);
      }
    }
    if (named.isEmpty()) {
      throw new PatchRefusal("TARGET_NOT_LOADED", className + " is not loaded in this JVM");
    }
    if (exact.isEmpty()) {
      throw new PatchRefusal(
          "NO_EXACT_METHOD", className + " declares no non-abstract " + method + descriptor);
    }
    Class<?> type = select(exact, request, className, method, descriptor);
    if (!inst.isModifiableClass(type)) {
      throw new PatchRefusal(
          "TARGET_NOT_MODIFIABLE", "the JVM reports " + className + " unmodifiable");
    }
    String artifact = null;
    if (request.artifactSha256 != null) {
      artifact = artifactSha256(type);
      if (artifact == null) {
        throw new PatchRefusal(
            "ARTIFACT_IDENTITY_UNAVAILABLE",
            className
                + " has no plain jar/file code source to hash ("
                + describeSource(type)
                + ")");
      }
      if (!artifact.equalsIgnoreCase(request.artifactSha256)) {
        throw new PatchRefusal(
            "ARTIFACT_HASH_MISMATCH",
            "asserted " + request.artifactSha256 + " but the loaded artifact is " + artifact);
      }
    }
    String fingerprint = null;
    if (request.fingerprint != null) {
      fingerprint = fingerprint(type, method, descriptor, true);
      if (!fingerprint.equalsIgnoreCase(request.fingerprint)) {
        throw new PatchRefusal(
            "BYTECODE_FINGERPRINT_MISMATCH",
            "asserted " + request.fingerprint + " but the loaded method is " + fingerprint);
      }
    }
    // Evidence for what the patch did not assert; failing to produce it is not a refusal.
    if (artifact == null) {
      artifact = artifactSha256(type);
    }
    if (fingerprint == null) {
      fingerprint = fingerprint(type, method, descriptor, false);
    }
    return new Resolved(
        type,
        new PatchIdentity.Evidence(
            loaders.selectorOf(type.getClassLoader()), artifact, fingerprint));
  }

  private Class<?> select(
      List<Class<?>> exact,
      PatchIdentity.Request request,
      String className,
      String method,
      String descriptor) {
    if (request.loader == null) {
      if (exact.size() > 1) {
        throw new PatchRefusal(
            "AMBIGUOUS_LOADER",
            exact.size()
                + " loaders define "
                + className
                + "."
                + method
                + descriptor
                + "; choose one with loader: "
                + candidates(exact));
      }
      if (request.strict) {
        throw new PatchRefusal(
            "MISSING_LOADER_SELECTOR",
            "a strict patch must assert a loader; the only candidate is " + candidates(exact));
      }
      return exact.get(0);
    }
    List<Class<?>> chosen = new ArrayList<>();
    for (Class<?> candidate : exact) {
      if (loaders.selectorOf(candidate.getClassLoader()).equals(request.loader)) {
        chosen.add(candidate);
      }
    }
    if (chosen.isEmpty()) {
      throw new PatchRefusal(
          "LOADER_MISMATCH",
          request.loader + " does not define " + className + "; candidates: " + candidates(exact));
    }
    return chosen.get(0);
  }

  private String candidates(List<Class<?>> classes) {
    StringBuilder out = new StringBuilder();
    for (Class<?> candidate : classes) {
      if (out.length() > 0) {
        out.append(", ");
      }
      String artifact = artifactSha256(candidate);
      out.append(loaders.selectorOf(candidate.getClassLoader()))
          .append(" (")
          .append(LoaderRegistry.describe(candidate.getClassLoader()))
          .append(", artifact_sha256=")
          .append(artifact == null ? "unavailable" : artifact)
          .append(')');
    }
    return out.toString();
  }

  private static boolean declares(Class<?> type, String method, String descriptor) {
    try {
      for (MethodDescription candidate :
          new TypeDescription.ForLoadedType(type).getDeclaredMethods()) {
        if (candidate.isMethod()
            && !candidate.isAbstract()
            && !candidate.isNative()
            && candidate.getName().equals(method)
            && candidate.getDescriptor().equals(descriptor)) {
          return true;
        }
      }
    } catch (LinkageError unresolvable) {
      // A class whose signatures cannot be resolved cannot be matched exactly.
    }
    return false;
  }

  /** Retransforms the class once with the capture armed; the class itself is left unchanged. */
  private synchronized String fingerprint(
      Class<?> type, String method, String descriptor, boolean required) {
    capture.arm(type, method, descriptor);
    try {
      inst.retransformClasses(type);
    } catch (Exception | LinkageError error) {
      if (required) {
        throw new PatchRefusal(
            "FINGERPRINT_UNAVAILABLE", "retransforming " + type.getName() + " failed: " + error);
      }
      return null;
    } finally {
      capture.disarm();
    }
    String fingerprint = capture.fingerprint();
    if (fingerprint == null && required) {
      throw new PatchRefusal(
          "FINGERPRINT_UNAVAILABLE",
          "no "
              + MethodFingerprint.VERSION
              + " fingerprint for "
              + type.getName()
              + ": "
              + capture.failure());
    }
    return fingerprint;
  }

  /** SHA-256 of the jar or file the class was loaded from, or null if there is no plain one. */
  String artifactSha256(Class<?> type) {
    try {
      ProtectionDomain domain = type.getProtectionDomain();
      CodeSource source = domain == null ? null : domain.getCodeSource();
      if (source == null
          || source.getLocation() == null
          || !"file".equals(source.getLocation().getProtocol())) {
        return null;
      }
      File file = new File(URI.create(source.getLocation().toString()));
      if (!file.isFile()) {
        return null;
      }
      String key = file.getPath();
      CachedHash cached = hashes.get(key);
      if (cached != null
          && cached.length == file.length()
          && cached.modified == file.lastModified()) {
        return cached.hash;
      }
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (InputStream in = Files.newInputStream(file.toPath())) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
          digest.update(buffer, 0, read);
        }
      }
      StringBuilder hex = new StringBuilder();
      for (byte b : digest.digest()) {
        hex.append(String.format(Locale.ROOT, "%02x", b & 255));
      }
      hashes.put(key, new CachedHash(file.length(), file.lastModified(), hex.toString()));
      return hex.toString();
    } catch (Exception | LinkageError error) {
      return null;
    }
  }

  private static String describeSource(Class<?> type) {
    ProtectionDomain domain = type.getProtectionDomain();
    CodeSource source = domain == null ? null : domain.getCodeSource();
    return source == null || source.getLocation() == null
        ? "no code source"
        : source.getLocation().getProtocol() + " location";
  }

  private static final class CachedHash {
    final long length;
    final long modified;
    final String hash;

    CachedHash(long length, long modified, String hash) {
      this.length = length;
      this.modified = modified;
      this.hash = hash;
    }
  }
}
