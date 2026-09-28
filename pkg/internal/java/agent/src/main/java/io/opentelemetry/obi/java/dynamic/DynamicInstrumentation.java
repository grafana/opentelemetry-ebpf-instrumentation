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
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.utility.JavaModule;

public final class DynamicInstrumentation {
  private static final int MAX_SYMBOLS = 100000;
  private final Instrumentation inst;
  private final Map<String, Long> probes = new ConcurrentHashMap<>();
  private final Map<String, Throwable> failures = new ConcurrentHashMap<>();
  private final Method add;
  private final Method remove;

  public DynamicInstrumentation(Instrumentation inst) throws Exception {
    this.inst = inst;
    Class<?> runtime = Class.forName(DynamicSpanRuntime.class.getName(), true, null);
    add = runtime.getMethod("add", String.class, long.class);
    remove = runtime.getMethod("remove", String.class, long.class);
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
                return false;
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
              return builder.visit(
                  Advice.to(MethodAdvice.class)
                      .on(
                          methods
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

  public synchronized void detach(long cookie) throws Exception {
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
  }

  private void retransform(String method) throws Exception {
    String name = method.substring(0, method.lastIndexOf('.'));
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
