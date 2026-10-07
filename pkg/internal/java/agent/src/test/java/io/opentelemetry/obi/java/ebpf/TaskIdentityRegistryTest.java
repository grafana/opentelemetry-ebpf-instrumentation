/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class TaskIdentityRegistryTest {
  @Test
  void assignsStableIdToSameTaskObject() {
    Object task = new Object();

    long first = TaskIdentityRegistry.idFor(task);

    assertEquals(first, TaskIdentityRegistry.idFor(task));
  }

  @Test
  void doesNotConflateDistinctTasksThatCompareEqual() {
    EqualTask first = new EqualTask();
    EqualTask second = new EqualTask();

    assertEquals(first, second);
    assertNotEquals(TaskIdentityRegistry.idFor(first), TaskIdentityRegistry.idFor(second));
  }

  @Test
  void hashBucketCollisionDoesNotConflateTasks() {
    EqualTask first = new EqualTask();
    EqualTask second = new EqualTask();
    TaskIdentityRegistry.IdentityReference firstKey =
        new TaskIdentityRegistry.IdentityReference(first, null, 1);
    TaskIdentityRegistry.IdentityReference secondKey =
        new TaskIdentityRegistry.IdentityReference(second, null, 1);

    assertEquals(firstKey.hashCode(), secondKey.hashCode());
    assertNotEquals(firstKey, secondKey);
  }

  private static final class EqualTask {
    @Override
    public boolean equals(Object other) {
      return other instanceof EqualTask;
    }

    @Override
    public int hashCode() {
      return 7;
    }
  }
}
