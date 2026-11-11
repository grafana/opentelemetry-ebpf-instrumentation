/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import net.bytebuddy.jar.asm.Type;

/**
 * Observe mode of a patch: count the calls of the exact method without changing what it does, and
 * optionally count the calls whose String argument contains a literal text. The predicate is closed
 * on purpose (one parameter, one literal, no pattern language) and meant for test fixtures, not as
 * a production classifier.
 */
public final class PatchObservation {
  /** Predicate argument index meaning "no predicate". */
  public static final int NO_ARGUMENT = -1;

  static final int MAX_LITERAL_BYTES = 256;

  private PatchObservation() {}

  /** Whether and how a patch observes instead of enforcing. */
  public static final class Request {
    final boolean observe;
    final int argument;
    final String contains;

    public Request(boolean observe, int argument, String contains) {
      this.observe = observe;
      this.argument = argument;
      this.contains = contains == null || contains.isEmpty() ? null : contains;
    }

    public static Request enforce() {
      return new Request(false, NO_ARGUMENT, null);
    }

    boolean hasPredicate() {
      return argument != NO_ARGUMENT;
    }

    /** Refuses a predicate that is not a literal over one String parameter of the descriptor. */
    void validate(String descriptor) {
      if (!observe) {
        if (hasPredicate() || contains != null) {
          throw new PatchRefusal("PREDICATE_INVALID", "a predicate needs observe mode");
        }
        return;
      }
      if (!hasPredicate()) {
        if (contains != null) {
          throw new PatchRefusal("PREDICATE_INVALID", "a literal needs an argument index");
        }
        return;
      }
      if (contains == null) {
        throw new PatchRefusal("PREDICATE_INVALID", "an argument index needs a literal");
      }
      if (contains.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > MAX_LITERAL_BYTES) {
        throw new PatchRefusal(
            "PREDICATE_INVALID", "the literal is longer than " + MAX_LITERAL_BYTES + " bytes");
      }
      Type[] parameters = Type.getArgumentTypes(descriptor);
      if (argument < 0 || argument >= parameters.length) {
        throw new PatchRefusal(
            "PREDICATE_INVALID",
            "argument " + argument + " does not exist; the method has " + parameters.length);
      }
      String type = parameters[argument].getDescriptor();
      if (!"Ljava/lang/String;".equals(type) && !"Ljava/lang/CharSequence;".equals(type)) {
        throw new PatchRefusal(
            "PREDICATE_INVALID", "argument " + argument + " is " + type + ", not a String");
      }
    }
  }

  /** What one observing patch has counted since it was attached. Times are epoch milliseconds. */
  public static final class Counters {
    public final long cookie;
    public final long calls;
    public final long predicateHits;
    public final boolean hasPredicate;
    public final long firstSeenMillis;
    public final long lastSeenMillis;
    public final long sinceMillis;

    Counters(
        long cookie,
        long calls,
        long predicateHits,
        boolean hasPredicate,
        long firstSeenMillis,
        long lastSeenMillis,
        long sinceMillis) {
      this.cookie = cookie;
      this.calls = calls;
      this.predicateHits = predicateHits;
      this.hasPredicate = hasPredicate;
      this.firstSeenMillis = firstSeenMillis;
      this.lastSeenMillis = lastSeenMillis;
      this.sinceMillis = sinceMillis;
    }
  }
}
