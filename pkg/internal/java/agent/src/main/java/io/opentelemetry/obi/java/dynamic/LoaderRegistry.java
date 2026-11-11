/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.dynamic;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Names class loaders by object identity. {@code identityHashCode} alone is not an identity (it
 * collides), so each loader gets a sequence number the first time it is seen. Loaders are held
 * weakly so the registry never keeps an application class loader alive. Selectors are meaningful
 * only inside this JVM.
 */
final class LoaderRegistry {
  static final String BOOTSTRAP = "loader:bootstrap";
  private final List<Entry> entries = new ArrayList<>();
  private long next = 1;

  synchronized String selectorOf(ClassLoader loader) {
    if (loader == null) {
      return BOOTSTRAP;
    }
    Iterator<Entry> iterator = entries.iterator();
    while (iterator.hasNext()) {
      Entry entry = iterator.next();
      ClassLoader known = entry.loader.get();
      if (known == null) {
        iterator.remove();
      } else if (known == loader) {
        return entry.selector;
      }
    }
    String selector = "loader:" + next++;
    entries.add(new Entry(selector, loader));
    return selector;
  }

  static String describe(ClassLoader loader) {
    return loader == null
        ? "bootstrap"
        : loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader));
  }

  private static final class Entry {
    final String selector;
    final WeakReference<ClassLoader> loader;

    Entry(String selector, ClassLoader loader) {
      this.selector = selector;
      this.loader = new WeakReference<>(loader);
    }
  }
}
