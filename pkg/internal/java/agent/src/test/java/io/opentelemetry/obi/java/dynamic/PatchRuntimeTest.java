/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class PatchRuntimeTest {
  private static final String STRING_DESCRIPTOR = "(Ljava/lang/String;)Ljava/lang/String;";
  private static final String TWO_ARG_DESCRIPTOR = "(Ljava/lang/String;I)Ljava/lang/String;";
  private static final long FAR_FUTURE = TimeUnit.HOURS.toNanos(1);

  @AfterEach
  void clear() {
    PatchRuntime.remove(Owner.class.getName(), "lookup", STRING_DESCRIPTOR, 1);
  }

  @Test
  void returnsConstantOnlyForTheExactDescriptor() {
    PatchRuntime.add(
        Owner.class.getName(), "lookup", STRING_DESCRIPTOR, "fixed", 1, nowPlus(FAR_FUTURE));

    assertEquals("fixed", PatchRuntime.enter(Owner.class, "lookup", STRING_DESCRIPTOR));
    assertNull(PatchRuntime.enter(Owner.class, "lookup", TWO_ARG_DESCRIPTOR));
    assertNull(PatchRuntime.enter(Owner.class, "other", STRING_DESCRIPTOR));
  }

  @Test
  void goesInertAtTheMonotonicDeadline() {
    PatchRuntime.add(Owner.class.getName(), "lookup", STRING_DESCRIPTOR, "fixed", 1, nowPlus(-1));

    assertNull(PatchRuntime.enter(Owner.class, "lookup", STRING_DESCRIPTOR));
  }

  @Test
  void removeOnlyDeletesTheMatchingCookie() {
    PatchRuntime.add(
        Owner.class.getName(), "lookup", STRING_DESCRIPTOR, "fixed", 2, nowPlus(FAR_FUTURE));

    PatchRuntime.remove(Owner.class.getName(), "lookup", STRING_DESCRIPTOR, 1);
    assertEquals("fixed", PatchRuntime.enter(Owner.class, "lookup", STRING_DESCRIPTOR));

    PatchRuntime.remove(Owner.class.getName(), "lookup", STRING_DESCRIPTOR, 2);
    assertNull(PatchRuntime.enter(Owner.class, "lookup", STRING_DESCRIPTOR));
  }

  @Test
  void failsOpenOnBadInput() {
    assertNull(PatchRuntime.enter(null, "lookup", STRING_DESCRIPTOR));
  }

  private static long nowPlus(long nanos) {
    return System.nanoTime() + nanos;
  }

  private static final class Owner {}
}
