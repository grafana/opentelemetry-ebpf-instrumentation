/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import java.util.concurrent.Future;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JavaFutureInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Future.class)
        .and(ElementMatchers.not(ElementMatchers.isInterface()));
  }

  public static boolean matches(Class<?> clazz) {
    return !clazz.isInterface() && Future.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(JavaExecutorInst.CancelFutureContextAdvice.class)
                    .on(
                        ElementMatchers.named("cancel")
                            .and(ElementMatchers.takesArguments(boolean.class))))
            .visit(
                Advice.to(CompleteFutureContextAdvice.class)
                    .on(ElementMatchers.named("run").and(ElementMatchers.takesArguments(0))));
  }

  @SuppressWarnings("unused")
  public static final class CompleteFutureContextAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void complete(@Advice.This Future<?> future) {
      io.opentelemetry.obi.java.ebpf.ThreadInfo.completeScheduledTaskContext(future);
    }
  }
}
