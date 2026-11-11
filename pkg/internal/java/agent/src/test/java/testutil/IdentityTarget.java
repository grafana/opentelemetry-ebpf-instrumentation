/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package testutil;

/** Loaded from two jars by two loaders in PatchIdentityProbeTarget; never used directly. */
public class IdentityTarget {
  public String lookup(String key) {
    return "original:" + key;
  }

  public String lookup(String key, int ignored) {
    return "original2:" + key;
  }
}
