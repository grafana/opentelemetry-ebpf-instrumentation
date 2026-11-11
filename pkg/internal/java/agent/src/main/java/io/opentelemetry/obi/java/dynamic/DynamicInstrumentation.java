/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import static net.bytebuddy.matcher.ElementMatchers.*;

import java.lang.instrument.Instrumentation;
import java.lang.ref.WeakReference;
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
  private final Method addObserve;
  private final Method patchCounters;
  private final PatchResolver resolver;

  public DynamicInstrumentation(Instrumentation inst) throws Exception {
    this.inst = inst;
    Class<?> runtime = Class.forName(DynamicSpanRuntime.class.getName(), true, null);
    add = runtime.getMethod("add", String.class, long.class);
    remove = runtime.getMethod("remove", String.class, long.class);
    Class<?> patchRuntime = Class.forName(PatchRuntime.class.getName(), true, null);
    addPatch =
        patchRuntime.getMethod(
            "add",
            ClassLoader.class,
            String.class,
            String.class,
            String.class,
            String.class,
            long.class,
            long.class);
    removePatch =
        patchRuntime.getMethod(
            "remove", ClassLoader.class, String.class, String.class, String.class, long.class);
    addObserve =
        patchRuntime.getMethod(
            "addObserve",
            ClassLoader.class,
            String.class,
            String.class,
            String.class,
            int.class,
            String.class,
            long.class,
            long.class);
    patchCounters = patchRuntime.getMethod("counters");
    // First, so its fingerprint capture sees class bytes before this agent's own transformer.
    resolver = new PatchResolver(inst);
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
                return hasPatchesFor(type.getName());
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
              ElementMatcher.Junction<MethodDescription> observed = none();
              for (Patch patch : patchedMethods(type.getName(), loader)) {
                if (patch.observe) {
                  observed = observed.or(patch.matcher());
                } else {
                  patched = patched.or(patch.matcher());
                }
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
                                  .and(not(isSynthetic()))))
                  .visit(
                      Advice.to(ObserveAdvice.class)
                          .on(
                              observed
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

  /**
   * Resolves the target to one method in one loader (refusing anything ambiguous or mismatched),
   * then patches exactly that class and returns the V0 evidence of what was resolved.
   */
  public synchronized PatchIdentity.Evidence attachPatch(
      String className,
      String method,
      String descriptor,
      String constant,
      long expiresAtMillis,
      long cookie,
      PatchIdentity.Request identity,
      PatchObservation.Request mode)
      throws Exception {
    mode.validate(descriptor);
    if (!mode.observe && !descriptor.endsWith(RETURN_STRING_SUFFIX)) {
      throw new IllegalArgumentException("A return patch needs a method returning String");
    }
    long remainingMillis = expiresAtMillis - System.currentTimeMillis();
    if (remainingMillis <= 0 || remainingMillis > MAX_PATCH_TTL_MILLIS) {
      throw new IllegalArgumentException("Patch expiry must be within the next 24 hours");
    }
    PatchResolver.Resolved resolved = resolver.resolve(className, method, descriptor, identity);
    // The deadline is monotonic so wall-clock jumps cannot extend or shorten the patch.
    long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(remainingMillis);
    Patch patch =
        new Patch(
            resolved.type,
            resolver.selectorOf(resolved.type.getClassLoader()),
            className,
            method,
            descriptor,
            constant,
            cookie,
            deadlineNanos,
            mode);
    Patch prior = patches.put(patch.key(), patch);
    installPatch(patch);
    try {
      retransformType(resolved.type);
    } catch (Exception error) {
      if (prior == null) {
        patches.remove(patch.key());
        removePatch.invoke(null, patch.loader(), className, method, descriptor, cookie);
      } else {
        patches.put(prior.key(), prior);
        installPatch(prior);
      }
      try {
        retransformType(resolved.type);
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
    return resolved.evidence;
  }

  private void installPatch(Patch patch) throws Exception {
    if (patch.observe) {
      addObserve.invoke(
          null,
          patch.loader(),
          patch.className,
          patch.method,
          patch.descriptor,
          patch.argument,
          patch.contains,
          patch.cookie,
          patch.deadlineNanos);
    } else {
      addPatch.invoke(
          null,
          patch.loader(),
          patch.className,
          patch.method,
          patch.descriptor,
          patch.constant,
          patch.cookie,
          patch.deadlineNanos);
    }
  }

  /**
   * Counters of the observing patches that are still installed. A patch that was detached, replaced
   * or expired is simply absent, so a caller can tell "unknown" from a count of zero.
   */
  @SuppressWarnings("unchecked")
  public List<PatchObservation.Counters> counters() throws Exception {
    List<PatchObservation.Counters> out = new ArrayList<>();
    for (long[] row : (List<long[]>) patchCounters.invoke(null)) {
      out.add(
          new PatchObservation.Counters(
              row[0], row[1], row[2], row[3] != 0, row[4], row[5], row[6]));
    }
    return out;
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
      removePatch.invoke(
          null, patch.loader(), patch.className, patch.method, patch.descriptor, cookie);
      patches.remove(patch.key(), patch);
      cancelPatchExpiry(cookie);
      retransformPatched(patch);
      return true;
    }
    return false;
  }

  private boolean hasPatchesFor(String className) {
    for (Patch patch : patches.values()) {
      if (patch.className.equals(className)) {
        return true;
      }
    }
    return false;
  }

  /** The patches that apply to this class name as loaded by this loader. */
  private List<Patch> patchedMethods(String className, ClassLoader loader) {
    List<Patch> matched = new ArrayList<>();
    for (Patch patch : patches.values()) {
      if (patch.className.equals(className) && patch.appliesTo(loader)) {
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
      removePatch.invoke(
          null, patch.loader(), patch.className, patch.method, patch.descriptor, patch.cookie);
      cancelPatchExpiry(patch.cookie);
    }
    patches.clear();
    for (Patch patch : removed) {
      retransformPatched(patch);
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

  /** Retransforms only the class a patch was resolved to, not same-named classes elsewhere. */
  private void retransformPatched(Patch patch) throws Exception {
    Class<?> type = patch.type.get();
    if (type != null) {
      retransformType(type);
    }
  }

  private void retransformType(Class<?> type) throws Exception {
    String name = type.getName();
    failures.remove(name);
    inst.retransformClasses(type);
    Throwable failure = failures.remove(name);
    if (failure != null) {
      throw new IllegalStateException("Retransforming " + name, failure);
    }
  }

  private boolean eligible(Class<?> type) {
    return !type.isArray()
        && !type.isPrimitive()
        && !excluded(type.getName())
        && inst.isModifiableClass(type);
  }

  static boolean excluded(String name) {
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
    final WeakReference<Class<?>> type;
    final String loaderSelector;
    final String className;
    final String method;
    final String descriptor;
    final String constant;
    final long cookie;
    final long deadlineNanos;
    final boolean observe;
    final int argument;
    final String contains;

    Patch(
        Class<?> type,
        String loaderSelector,
        String className,
        String method,
        String descriptor,
        String constant,
        long cookie,
        long deadlineNanos,
        PatchObservation.Request mode) {
      this.observe = mode.observe;
      this.argument = mode.argument;
      this.contains = mode.contains;
      this.type = new WeakReference<>(type);
      this.loaderSelector = loaderSelector;
      this.className = className;
      this.method = method;
      this.descriptor = descriptor;
      this.constant = constant;
      this.cookie = cookie;
      this.deadlineNanos = deadlineNanos;
    }

    ClassLoader loader() {
      Class<?> resolved = type.get();
      return resolved == null ? null : resolved.getClassLoader();
    }

    boolean appliesTo(ClassLoader candidate) {
      Class<?> resolved = type.get();
      return resolved != null && resolved.getClassLoader() == candidate;
    }

    /** Loader identity is part of the key, so same-named classes in two loaders do not collide. */
    String key() {
      return loaderSelector + "|" + className + "." + method + descriptor;
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

  /**
   * Counts calls of an observed method. It cannot skip or alter the method, and it never throws.
   */
  public static final class ObserveAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(
        @Advice.Origin Class<?> owner,
        @Advice.Origin("#m") String method,
        @Advice.Origin("#d") String descriptor,
        @Advice.AllArguments Object[] arguments) {
      PatchRuntime.observe(owner, method, descriptor, arguments);
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
