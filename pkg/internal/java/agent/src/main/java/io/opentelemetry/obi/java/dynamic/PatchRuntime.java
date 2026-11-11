/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Bootstrap-visible runtime for live patches. It deliberately has no Byte Buddy or SDK dependency
 * and keeps no per-call state, so nested and concurrent calls are all patched. A patch belongs to
 * one class loader: a same-named class in another loader is never matched. Loaders are held weakly.
 *
 * <p>A patch is either enforcing (it returns a constant) or observing (it only counts calls and
 * never changes what the method does).
 */
public final class PatchRuntime {
  private static final ConcurrentHashMap<String, Patch[]> PATCHES = new ConcurrentHashMap<>();

  private PatchRuntime() {}

  private static final class Patch {
    final WeakReference<ClassLoader> loader;
    final boolean bootstrap;
    final String constant;
    final long cookie;
    final long deadlineNanos;
    // Observe mode only: counters, and the optional literal over one argument.
    final boolean observe;
    final int argument;
    final String contains;
    final long sinceMillis = System.currentTimeMillis();
    final LongAdder calls = new LongAdder();
    final LongAdder hits = new LongAdder();
    final AtomicLong firstSeen = new AtomicLong();
    final AtomicLong lastSeen = new AtomicLong();

    Patch(
        ClassLoader loader,
        String constant,
        long cookie,
        long deadlineNanos,
        boolean observe,
        int argument,
        String contains) {
      this.loader = new WeakReference<>(loader);
      this.bootstrap = loader == null;
      this.constant = constant;
      this.cookie = cookie;
      this.deadlineNanos = deadlineNanos;
      this.observe = observe;
      this.argument = argument;
      this.contains = contains;
    }

    boolean appliesTo(ClassLoader candidate) {
      return bootstrap ? candidate == null : candidate != null && loader.get() == candidate;
    }

    boolean dead() {
      return !bootstrap && loader.get() == null;
    }
  }

  /** Adds a patch for one loader's class, replacing that loader's earlier patch of the method. */
  public static void add(
      ClassLoader loader,
      String className,
      String method,
      String descriptor,
      String constant,
      long cookie,
      long deadlineNanos) {
    Patch added = new Patch(loader, constant, cookie, deadlineNanos, false, -1, null);
    PATCHES.compute(
        key(className, method, descriptor),
        (name, current) -> without(current, loader, true, 0, added));
  }

  /**
   * Adds an observing patch for one loader's class: it counts calls (and, with an argument index
   * and a literal, the calls whose String argument contains it) and never alters the method.
   */
  public static void addObserve(
      ClassLoader loader,
      String className,
      String method,
      String descriptor,
      int argument,
      String contains,
      long cookie,
      long deadlineNanos) {
    Patch added = new Patch(loader, null, cookie, deadlineNanos, true, argument, contains);
    PATCHES.compute(
        key(className, method, descriptor),
        (name, current) -> without(current, loader, true, 0, added));
  }

  /** Removes the loader's patch, but only if it still carries this cookie. */
  public static void remove(
      ClassLoader loader, String className, String method, String descriptor, long cookie) {
    PATCHES.computeIfPresent(
        key(className, method, descriptor),
        (name, current) -> without(current, loader, false, cookie, null));
  }

  /**
   * Returns the constant to return instead of running the method, or null to run the original code.
   * Any failure here must leave the application untouched, so it fails open.
   */
  public static Object enter(Class<?> owner, String method, String descriptor) {
    try {
      Patch[] candidates = PATCHES.get(key(owner.getName(), method, descriptor));
      if (candidates == null) {
        return null;
      }
      ClassLoader loader = owner.getClassLoader();
      for (Patch patch : candidates) {
        if (patch.appliesTo(loader)) {
          if (patch.observe) {
            return null;
          }
          return System.nanoTime() - patch.deadlineNanos >= 0 ? null : patch.constant;
        }
      }
      return null;
    } catch (Throwable error) {
      return null;
    }
  }

  /**
   * Counts one call of an observed method. Never throws and never changes the call: any failure
   * here is dropped, so the application is untouched.
   */
  public static void observe(Class<?> owner, String method, String descriptor, Object[] arguments) {
    try {
      Patch[] candidates = PATCHES.get(key(owner.getName(), method, descriptor));
      if (candidates == null) {
        return;
      }
      ClassLoader loader = owner.getClassLoader();
      for (Patch patch : candidates) {
        if (!patch.appliesTo(loader)) {
          continue;
        }
        if (!patch.observe || System.nanoTime() - patch.deadlineNanos >= 0) {
          return;
        }
        long now = System.currentTimeMillis();
        patch.calls.increment();
        patch.firstSeen.compareAndSet(0, now);
        patch.lastSeen.set(now);
        if (patch.argument >= 0
            && arguments != null
            && patch.argument < arguments.length
            && arguments[patch.argument] instanceof CharSequence
            && arguments[patch.argument].toString().contains(patch.contains)) {
          patch.hits.increment();
        }
        return;
      }
    } catch (Throwable error) {
      // Fail open: counting must never affect the application.
    }
  }

  /**
   * Counters of every live observing patch, as {cookie, calls, hits, hasPredicate (0/1), firstSeen,
   * lastSeen, since}. A patch that was removed or expired has no entry: its counters are unknown,
   * not zero.
   */
  public static List<long[]> counters() {
    List<long[]> out = new ArrayList<>();
    for (Patch[] patches : PATCHES.values()) {
      for (Patch patch : patches) {
        if (patch.observe && !patch.dead()) {
          out.add(
              new long[] {
                patch.cookie,
                patch.calls.sum(),
                patch.hits.sum(),
                patch.argument >= 0 ? 1 : 0,
                patch.firstSeen.get(),
                patch.lastSeen.get(),
                patch.sinceMillis
              });
        }
      }
    }
    return out;
  }

  /**
   * Copy of current without this loader's patch (any cookie, or only the given one) and without
   * patches of collected loaders, plus added. Null when nothing is left.
   */
  private static Patch[] without(
      Patch[] current, ClassLoader loader, boolean anyCookie, long cookie, Patch added) {
    int size = 0;
    Patch[] kept = new Patch[(current == null ? 0 : current.length) + 1];
    if (current != null) {
      for (Patch patch : current) {
        boolean same = patch.appliesTo(loader);
        if (patch.dead() || (same && (anyCookie || patch.cookie == cookie))) {
          continue;
        }
        kept[size++] = patch;
      }
    }
    if (added != null) {
      kept[size++] = added;
    }
    if (size == 0) {
      return null;
    }
    return java.util.Arrays.copyOf(kept, size);
  }

  private static String key(String className, String method, String descriptor) {
    return className + "." + method + descriptor;
  }
}
