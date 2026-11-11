/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

/**
 * A patch target that could not be resolved to exactly one method, or whose asserted identity does
 * not match what the JVM has loaded. {@link #reason()} is a stable code; the message starts with it
 * so it survives the control socket's plain-string error reply.
 */
public final class PatchRefusal extends IllegalArgumentException {
  private static final long serialVersionUID = 1L;

  private final String reason;

  public PatchRefusal(String reason, String detail) {
    super(reason + ": " + detail);
    this.reason = reason;
  }

  public String reason() {
    return reason;
  }

  @Override
  public String toString() {
    return "PatchRefusal " + getMessage();
  }
}
