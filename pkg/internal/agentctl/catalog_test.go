// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agentctl

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
)

func TestCatalogLimitsAndInvalidation(t *testing.T) {
	cfg := config.DefaultDynamicInstrumentationConfig()
	cfg.SymbolCacheEntries = 2
	cfg.SymbolCacheBytes = 100
	cfg.MaxCachedBinaryBytes = 80
	cache := NewCatalog(cfg)
	cache.Put(1, 10, 1, []string{"first"})
	cache.Put(2, 10, 1, []string{"second"})
	_, found := cache.Get(1, 10, 1)
	require.True(t, found)
	cache.Put(3, 10, 1, []string{"third"})
	_, found = cache.Get(2, 10, 1)
	require.False(t, found, "least recently used process must be evicted")
	cache.Put(1, 10, 2, []string{string(make([]byte, 81))})
	_, found = cache.Get(1, 10, 2)
	require.False(t, found, "oversized catalogs must not be cached")
	cache.Put(1, 10, 2, []string{"updated"})
	_, found = cache.Get(1, 10, 1)
	require.False(t, found, "prior revisions must be evicted")
	_, found = cache.Get(1, 11, 2)
	require.False(t, found, "recycled PIDs must not reuse a catalog")
	cache.Remove(1)
	cache.Remove(3)
	require.Zero(t, cache.bytes)
	cfg.MaxCachedBinaryBytes = 0
	disabled := NewCatalog(cfg)
	disabled.Put(1, 10, 1, []string{"ignored"})
	_, found = disabled.Get(1, 10, 1)
	require.False(t, found)
}
