/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import static net.bytebuddy.matcher.ElementMatchers.*;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.utility.JavaModule;

public final class DynamicInstrumentation {
  private static final int MAX_SYMBOLS = 100000;
  private static final long MAX_PATCH_TTL_MILLIS = TimeUnit.HOURS.toMillis(24);
  private static final String RETURN_STRING_SUFFIX = ")Ljava/lang/String;";
  private final Instrumentation inst;
  private final Map<String, Long> probes = new ConcurrentHashMap<>();
  private final Map<String, Throwable> failures = new ConcurrentHashMap<>();
  private final Map<String, Patch> patches = new ConcurrentHashMap<>();
  private final Map<Long, ScheduledFuture<?>> patchExpiry = new ConcurrentHashMap<>();
  private final ScheduledExecutorService expiryTimer =
      Executors.newSingleThreadScheduledExecutor(
          task -> {
            Thread thread = new Thread(task, "obi-dynamic-patch-expiry");
            thread.setDaemon(true);
            return thread;
          });
  private final Method add;
  private final Method remove;
  private final Method addPatch;
  private final Method removePatch;

  public DynamicInstrumentation(Instrumentation inst) throws Exception {
    this.inst = inst;
    Class<?> runtime = Class.forName(DynamicSpanRuntime.class.getName(), true, null);
    add = runtime.getMethod("add", String.class, long.class);
    remove = runtime.getMethod("remove", String.class, long.class);
    Class<?> patchRuntime = Class.forName(PatchRuntime.class.getName(), true, null);
    addPatch =
        patchRuntime.getMethod(
            "add", String.class, String.class, String.class, String.class, long.class, long.class);
    removePatch =
        patchRuntime.getMethod("remove", String.class, String.class, String.class, long.class);
    new AgentBuilder.Default()
        .disableClassFormatChanges()
        .ignore(
            new ElementMatcher.Junction.AbstractBase<TypeDescription>() {
              @Override
              public boolean matches(TypeDescription type) {
                return excluded(type.getName());
              }
            })
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
        .with(
            new AgentBuilder.Listener.Adapter() {
              @Override
              public void onError(
                  String name,
                  ClassLoader loader,
                  JavaModule module,
                  boolean loaded,
                  Throwable error) {
                failures.put(name, error);
              }
            })
        .type(
            new ElementMatcher.Junction.AbstractBase<TypeDescription>() {
              @Override
              public boolean matches(TypeDescription type) {
                for (String name : probes.keySet()) {
                  if (name.substring(0, name.lastIndexOf('.')).equals(type.getName())) {
                    return true;
                  }
                }
                return !patchedMethods(type.getName()).isEmpty();
              }
            })
        .transform(
            (builder, type, loader, module, domain) -> {
              net.bytebuddy.matcher.ElementMatcher.Junction<
                      net.bytebuddy.description.method.MethodDescription>
                  methods = none();
              for (String name : probes.keySet()) {
                int separator = name.lastIndexOf('.');
                if (name.substring(0, separator).equals(type.getName())) {
                  methods = methods.or(named(name.substring(separator + 1)));
                }
              }
              ElementMatcher.Junction<MethodDescription> patched = none();
              for (Patch patch : patchedMethods(type.getName())) {
                patched = patched.or(patch.matcher());
              }
              return builder
                  .visit(
                      Advice.to(MethodAdvice.class)
                          .on(
                              methods
                                  .and(isMethod())
                                  .and(not(isAbstract()))
                                  .and(not(isNative()))
                                  .and(not(isSynthetic()))))
                  .visit(
                      Advice.to(PatchAdvice.class)
                          .on(
                              patched
                                  .and(isMethod())
                                  .and(not(isAbstract()))
                                  .and(not(isNative()))
                                  .and(not(isSynthetic()))));
            })
        .installOn(inst);
  }

  public synchronized List<String> symbols() {
    Set<String> names = new TreeSet<>();
    for (Class<?> type : inst.getAllLoadedClasses()) {
      if (!eligible(type)) {
        continue;
      }
      try {
        for (Method method : type.getDeclaredMethods()) {
          if (!Modifier.isNative(method.getModifiers())
              && !Modifier.isAbstract(method.getModifiers())
              && !method.isSynthetic()) {
            names.add(type.getName() + "." + method.getName());
            if (names.size() > MAX_SYMBOLS) {
              throw new IllegalStateException(
                  "Java method catalog exceeds " + MAX_SYMBOLS + " methods");
            }
          }
        }
      } catch (LinkageError | SecurityException ignored) {
      }
    }
    return new ArrayList<>(names);
  }

  public synchronized void attach(String method, long cookie) throws Exception {
    if (probes.size() >= 4096) {
      throw new IllegalArgumentException("Java dynamic probe limit reached");
    }
    if (!symbols().contains(method)) {
      throw new IllegalArgumentException("No loaded, modifiable Java method: " + method);
    }
    Long prior = probes.put(method, cookie);
    add.invoke(null, method, cookie);
    try {
      retransform(method);
    } catch (Exception error) {
      if (prior == null) {
        probes.remove(method);
        remove.invoke(null, method, cookie);
      } else {
        probes.put(method, prior);
        add.invoke(null, method, prior);
      }
      try {
        retransform(method);
      } catch (Exception rollback) {
        error.addSuppressed(rollback);
      }
      throw error;
    }
  }

  public synchronized void attachPatch(
      String className,
      String method,
      String descriptor,
      String constant,
      long expiresAtMillis,
      long cookie)
      throws Exception {
    if (!descriptor.endsWith(RETURN_STRING_SUFFIX)) {
      throw new IllegalArgumentException("A return patch needs a method returning String");
    }
    long remainingMillis = expiresAtMillis - System.currentTimeMillis();
    if (remainingMillis <= 0 || remainingMillis > MAX_PATCH_TTL_MILLIS) {
      throw new IllegalArgumentException("Patch expiry must be within the next 24 hours");
    }
    if (!hasLoadedMethod(className, method, descriptor)) {
      throw new IllegalArgumentException(
          "No loaded, modifiable Java method: " + className + "." + method + descriptor);
    }
    // The deadline is monotonic so wall-clock jumps cannot extend or shorten the patch.
    long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(remainingMillis);
    Patch patch = new Patch(className, method, descriptor, constant, cookie, deadlineNanos);
    Patch prior = patches.put(patch.key(), patch);
    addPatch.invoke(null, className, method, descriptor, constant, cookie, deadlineNanos);
    try {
      retransformClass(className);
    } catch (Exception error) {
      if (prior == null) {
        patches.remove(patch.key());
        removePatch.invoke(null, className, method, descriptor, cookie);
      } else {
        patches.put(prior.key(), prior);
        addPatch.invoke(
            null, className, method, descriptor, prior.constant, prior.cookie, prior.deadlineNanos);
      }
      try {
        retransformClass(className);
      } catch (Exception rollback) {
        error.addSuppressed(rollback);
      }
      throw error;
    }
    if (prior != null) {
      cancelPatchExpiry(prior.cookie);
    }
    patchExpiry.put(
        cookie,
        expiryTimer.schedule(() -> expirePatch(cookie), remainingMillis, TimeUnit.MILLISECONDS));
  }

  private void expirePatch(long cookie) {
    try {
      detach(cookie);
    } catch (Exception error) {
      // The per-call deadline check already makes the patch inert; reconnect cleanup retries.
    }
  }

  private void cancelPatchExpiry(long cookie) {
    ScheduledFuture<?> timer = patchExpiry.remove(cookie);
    if (timer != null) {
      timer.cancel(false);
    }
  }

  private boolean detachPatch(long cookie) throws Exception {
    for (Patch patch : patches.values()) {
      if (patch.cookie != cookie) {
        continue;
      }
      removePatch.invoke(null, patch.className, patch.method, patch.descriptor, cookie);
      patches.remove(patch.key(), patch);
      cancelPatchExpiry(cookie);
      retransformClass(patch.className);
      return true;
    }
    return false;
  }

  private boolean hasLoadedMethod(String className, String method, String descriptor) {
    for (Class<?> type : inst.getAllLoadedClasses()) {
      if (!eligible(type) || !type.getName().equals(className)) {
        continue;
      }
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
      } catch (LinkageError ignored) {
      }
    }
    return false;
  }

  private List<Patch> patchedMethods(String className) {
    List<Patch> matched = new ArrayList<>();
    for (Patch patch : patches.values()) {
      if (patch.className.equals(className)) {
        matched.add(patch);
      }
    }
    return matched;
  }

  public synchronized void detach(long cookie) throws Exception {
    if (detachPatch(cookie)) {
      return;
    }
    for (Map.Entry<String, Long> entry : probes.entrySet()) {
      if (entry.getValue() != cookie) {
        continue;
      }
      String method = entry.getKey();
      remove.invoke(null, method, cookie);
      probes.remove(method, cookie);
      retransform(method);
      return;
    }
  }

  public synchronized void reset() throws Exception {
    List<String> methods = new ArrayList<>(probes.keySet());
    for (String method : methods) {
      remove.invoke(null, method, probes.get(method));
    }
    probes.clear();
    for (String method : methods) {
      retransform(method);
    }
    List<Patch> removed = new ArrayList<>(patches.values());
    for (Patch patch : removed) {
      removePatch.invoke(null, patch.className, patch.method, patch.descriptor, patch.cookie);
      cancelPatchExpiry(patch.cookie);
    }
    patches.clear();
    for (Patch patch : removed) {
      retransformClass(patch.className);
    }
  }

  private void retransform(String method) throws Exception {
    retransformClass(method.substring(0, method.lastIndexOf('.')));
  }

  private void retransformClass(String name) throws Exception {
    for (Class<?> type : inst.getAllLoadedClasses()) {
      if (!eligible(type) || !type.getName().equals(name)) {
        continue;
      }
      failures.remove(name);
      inst.retransformClasses(type);
      Throwable failure = failures.remove(name);
      if (failure != null) {
        throw new IllegalStateException("Retransforming " + name, failure);
      }
    }
  }

  private boolean eligible(Class<?> type) {
    return !type.isArray()
        && !type.isPrimitive()
        && !excluded(type.getName())
        && inst.isModifiableClass(type);
  }

  private static boolean excluded(String name) {
    return name.startsWith("java.")
        || name.startsWith("javax.")
        || name.startsWith("jdk.")
        || name.startsWith("sun.")
        || name.startsWith("com.sun.")
        || name.startsWith("net.bytebuddy.")
        || name.startsWith("io.opentelemetry.")
        || name.contains("$$Lambda$");
  }

  private static final class Patch {
    final String className;
    final String method;
    final String descriptor;
    final String constant;
    final long cookie;
    final long deadlineNanos;

    Patch(
        String className,
        String method,
        String descriptor,
        String constant,
        long cookie,
        long deadlineNanos) {
      this.className = className;
      this.method = method;
      this.descriptor = descriptor;
      this.constant = constant;
      this.cookie = cookie;
      this.deadlineNanos = deadlineNanos;
    }

    String key() {
      return className + "." + method + descriptor;
    }

    ElementMatcher.Junction<MethodDescription> matcher() {
      return new ElementMatcher.Junction.AbstractBase<MethodDescription>() {
        @Override
        public boolean matches(MethodDescription candidate) {
          return candidate.getName().equals(method) && candidate.getDescriptor().equals(descriptor);
        }
      };
    }
  }

  /**
   * Skips the original body and returns the patch constant. The enter hook never throws, so an
   * internal failure runs the original code. Unlike {@link MethodAdvice}, nothing here suppresses
   * exceptions from the patched method itself.
   */
  public static final class PatchAdvice {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static Object enter(
        @Advice.Origin Class<?> owner,
        @Advice.Origin("#m") String method,
        @Advice.Origin("#d") String descriptor) {
      return PatchRuntime.enter(owner, method, descriptor);
    }

    @Advice.OnMethodExit
    public static void exit(
        @Advice.Enter Object constant,
        @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
      if (constant != null) {
        result = constant;
      }
    }
  }

  public static final class MethodAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static DynamicSpanRuntime.Invocation enter(
        @Advice.Origin Class<?> owner,
        @Advice.Origin("#m") String method,
        @Advice.Origin("#r") String result,
        @Advice.AllArguments Object[] arguments) {
      return DynamicSpanRuntime.enter(owner, method, arguments, !"void".equals(result));
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Enter DynamicSpanRuntime.Invocation call,
        @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object result,
        @Advice.Thrown Throwable error) {
      DynamicSpanRuntime.exit(call, result, error);
    }
  }
}
