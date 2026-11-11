/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

/** What a patch asserts about its target (all optional unless strict) and what was resolved. */
public final class PatchIdentity {
  private PatchIdentity() {}

  /** Identity assertions that come with a patch. Blank fields are not asserted. */
  public static final class Request {
    final boolean strict;
    final String loader;
    final String artifactSha256;
    final String fingerprint;

    public Request(boolean strict, String loader, String artifactSha256, String fingerprint) {
      this.strict = strict;
      this.loader = blankToNull(loader);
      this.artifactSha256 = blankToNull(artifactSha256);
      this.fingerprint = blankToNull(fingerprint);
    }

    public static Request none() {
      return new Request(false, null, null, null);
    }
  }

  /** The V0 evidence for the one method that was patched. Unavailable parts are empty strings. */
  public static final class Evidence {
    public final String loader;
    public final String artifactSha256;
    public final String fingerprint;

    Evidence(String loader, String artifactSha256, String fingerprint) {
      this.loader = loader;
      this.artifactSha256 = artifactSha256 == null ? "" : artifactSha256;
      this.fingerprint = fingerprint == null ? "" : fingerprint;
    }
  }

  private static String blankToNull(String value) {
    return value == null || value.trim().isEmpty() ? null : value.trim();
  }
}
