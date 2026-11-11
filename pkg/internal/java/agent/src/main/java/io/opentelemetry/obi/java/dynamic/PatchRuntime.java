/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Bootstrap-visible runtime for live patches. It deliberately has no Byte Buddy or SDK dependency
 * and keeps no per-call state, so nested and concurrent calls are all patched.
 */
public final class PatchRuntime {
  private static final ConcurrentHashMap<String, Patch> PATCHES = new ConcurrentHashMap<>();

  private PatchRuntime() {}

  private static final class Patch {
    final String constant;
    final long cookie;
    final long deadlineNanos;

    Patch(String constant, long cookie, long deadlineNanos) {
      this.constant = constant;
      this.cookie = cookie;
      this.deadlineNanos = deadlineNanos;
    }
  }

  public static void add(
      String className,
      String method,
      String descriptor,
      String constant,
      long cookie,
      long deadlineNanos) {
    PATCHES.put(key(className, method, descriptor), new Patch(constant, cookie, deadlineNanos));
  }

  public static void remove(String className, String method, String descriptor, long cookie) {
    PATCHES.computeIfPresent(
        key(className, method, descriptor), (name, patch) -> patch.cookie == cookie ? null : patch);
  }

  /**
   * Returns the constant to return instead of running the method, or null to run the original code.
   * Any failure here must leave the application untouched, so it fails open.
   */
  public static Object enter(Class<?> owner, String method, String descriptor) {
    try {
      Patch patch = PATCHES.get(key(owner.getName(), method, descriptor));
      if (patch == null || System.nanoTime() - patch.deadlineNanos >= 0) {
        return null;
      }
      return patch.constant;
    } catch (Throwable error) {
      return null;
    }
  }

  private static String key(String className, String method, String descriptor) {
    return className + "." + method + descriptor;
  }
}
