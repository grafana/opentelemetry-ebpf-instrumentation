// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

func TestSymbolCacheBudgetAndEviction(t *testing.T) {
	path, err := os.Executable()
	require.NoError(t, err)
	ef, err := elf.Open(path)
	require.NoError(t, err)
	defer ef.Close()
	cfg := config.DefaultDynamicInstrumentationConfig()
	cfg.SymbolCacheEntries = 1
	cfg.SymbolCacheBytes = 1 << 30
	cfg.MaxCachedBinaryBytes = 1 << 30
	cache := newSymbolCache(cfg)
	symbols, err := cache.symbols(path, ef)
	require.NoError(t, err)
	require.NotEmpty(t, symbols)
	require.Equal(t, 1, cache.entries.Len())
	cost := cache.bytes
	require.Positive(t, cost)
	_, err = cache.symbols(path, ef)
	require.NoError(t, err)
	require.Equal(t, cost, cache.bytes)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	copyPath := filepath.Join(t.TempDir(), "same-name-new-inode")
	require.NoError(t, os.WriteFile(copyPath, data, 0o700))
	_, err = cache.symbols(copyPath, ef)
	require.NoError(t, err)
	require.Equal(t, 1, cache.entries.Len())
	require.Equal(t, cost, cache.bytes)
	cfg.MaxCachedBinaryBytes = 1
	uncached := newSymbolCache(cfg)
	_, err = uncached.symbols(path, ef)
	require.NoError(t, err)
	require.Zero(t, uncached.entries.Len())
	require.Zero(t, uncached.bytes)
}

func TestSymbolGlobResolution(t *testing.T) {
	tracer := &ProcessTracer{symbols: newSymbolCache(config.DefaultDynamicInstrumentationConfig())}
	names, err := tracer.ResolveLiveSymbols(app.PID(os.Getpid()), "*TestSymbol{GlobResolution,CacheBudgetAndEviction}")
	require.NoError(t, err)
	require.Len(t, names, 2)
	exact, err := tracer.ResolveLiveSymbols(app.PID(os.Getpid()), names[0])
	require.NoError(t, err)
	require.Equal(t, []string{names[0]}, exact)
	_, err = tracer.ResolveLiveSymbols(app.PID(os.Getpid()), "no.such.function")
	require.ErrorContains(t, err, "matched no symbols")
}
