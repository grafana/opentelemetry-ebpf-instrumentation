/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;

/**
 * Assigns stable, collision-free (within a process lifetime) IDs without retaining task objects.
 */
final class TaskIdentityRegistry {
  private static final ReferenceQueue<Object> COLLECTED_TASKS = new ReferenceQueue<>();
  private static final Map<IdentityReference, Long> IDS = new HashMap<>();
  private static long nextId = 1;

  private TaskIdentityRegistry() {}

  static synchronized long idFor(Object task) {
    if (task == null) {
      throw new NullPointerException("task");
    }
    expungeCollectedTasks();
    IdentityReference lookup = new IdentityReference(task, null);
    Long existing = IDS.get(lookup);
    if (existing != null) {
      return existing;
    }

    if (nextId == 0) {
      throw new IllegalStateException("Java task identity space exhausted");
    }
    long id = nextId++;
    IDS.put(new IdentityReference(task, COLLECTED_TASKS), id);
    return id;
  }

  private static void expungeCollectedTasks() {
    IdentityReference collected;
    while ((collected = (IdentityReference) COLLECTED_TASKS.poll()) != null) {
      IDS.remove(collected);
    }
  }

  static final class IdentityReference extends WeakReference<Object> {
    private final int hashCode;

    IdentityReference(Object referent, ReferenceQueue<Object> queue) {
      this(referent, queue, System.identityHashCode(referent));
    }

    IdentityReference(Object referent, ReferenceQueue<Object> queue, int hashCode) {
      super(referent, queue);
      // Hash collisions only select a bucket; equals compares live referents by identity.
      this.hashCode = hashCode;
    }

    @Override
    public int hashCode() {
      return hashCode;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof IdentityReference)) {
        return false;
      }
      Object referent = get();
      return referent != null && referent == ((IdentityReference) other).get();
    }
  }
}
