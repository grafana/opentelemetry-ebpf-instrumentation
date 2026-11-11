/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class PatchObservationTest {
  private static final String LOOKUP = "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;";
  private static final ClassLoader LOADER = Owner.class.getClassLoader();
  private static final String OWNER = Owner.class.getName();

  @AfterEach
  void clear() {
    PatchRuntime.remove(LOADER, OWNER, "lookup", LOOKUP, 1);
  }

  private static PatchObservation.Request observe(int argument, String contains) {
    return new PatchObservation.Request(true, argument, contains);
  }

  @Test
  void aPredicateMustBeALiteralOverOneStringParameter() {
    assertDoesNotThrow(() -> observe(-1, null).validate(LOOKUP));
    assertDoesNotThrow(() -> observe(1, "x").validate(LOOKUP));
    assertDoesNotThrow(
        () -> observe(0, "x").validate("(Ljava/lang/CharSequence;)Ljava/lang/String;"));
    for (PatchObservation.Request bad :
        new PatchObservation.Request[] {
          observe(0, "x"), // Object, not a String
          observe(2, "x"), // no such parameter
          observe(-2, "x"),
          observe(1, null), // index without literal
          observe(-1, "x"), // literal without index
          new PatchObservation.Request(false, 1, "x"), // predicate on an enforcing patch
        }) {
      PatchRefusal refusal = assertThrows(PatchRefusal.class, () -> bad.validate(LOOKUP));
      assertEquals("PREDICATE_INVALID", refusal.reason());
    }
  }

  @Test
  void countsCallsAndPredicateHitsAndNeverReturnsAConstant() {
    PatchRuntime.addObserve(
        LOADER, OWNER, "lookup", LOOKUP, 1, "canary", 1, System.nanoTime() + hour());

    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"event", "benign"});
    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"canary", "benign"});
    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"event", "a canary here"});
    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"event", null});
    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"event"});
    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, null);

    assertNull(PatchRuntime.enter(Owner.class, "lookup", LOOKUP));
    long[] row = only();
    assertEquals(1, row[0]);
    assertEquals(6, row[1]);
    assertEquals(1, row[2]);
    assertEquals(1, row[3]);
    assertTrue(row[4] > 0 && row[5] >= row[4] && row[6] > 0);
  }

  @Test
  void aNeverCalledMethodHasAKnownZeroAndARemovedPatchHasNone() {
    PatchRuntime.addObserve(
        LOADER, OWNER, "lookup", LOOKUP, -1, null, 1, System.nanoTime() + hour());
    long[] row = only();
    assertEquals(0, row[1]);
    assertEquals(0, row[4]);
    assertEquals(0, row[5]);

    PatchRuntime.remove(LOADER, OWNER, "lookup", LOOKUP, 1);

    assertTrue(PatchRuntime.counters().isEmpty(), "removed counters must be absent, not zero");
  }

  @Test
  void stopsCountingAtTheDeadline() {
    PatchRuntime.addObserve(LOADER, OWNER, "lookup", LOOKUP, -1, null, 1, System.nanoTime() - 1);

    PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"e", "k"});

    assertEquals(0, only()[1]);
  }

  @Test
  void aBrokenPredicateInputNeverThrows() {
    PatchRuntime.addObserve(LOADER, OWNER, "lookup", LOOKUP, 1, "x", 1, System.nanoTime() + hour());
    assertDoesNotThrow(() -> PatchRuntime.observe(null, "lookup", LOOKUP, new Object[] {"e", "x"}));
    assertDoesNotThrow(
        () ->
            PatchRuntime.observe(Owner.class, "lookup", LOOKUP, new Object[] {"e", new Object()}));
    long[] row = only();
    assertEquals(
        1, row[1], "the call with a non-String argument is counted, the null owner is not");
    assertEquals(0, row[2]);
  }

  private static long[] only() {
    List<long[]> rows = PatchRuntime.counters();
    assertEquals(1, rows.size());
    return rows.get(0);
  }

  private static long hour() {
    return TimeUnit.HOURS.toNanos(1);
  }

  static final class Owner {}
}
