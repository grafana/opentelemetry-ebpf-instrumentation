// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestJavaDynamicControlAndCatalog(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	cfg := config.DefaultDynamicInstrumentationConfig()
	registry := NewDynamicRegistry(context.Background(), cfg, ebpfcommon.NewEBPFEventContext())
	pid := app.PID(os.Getpid())
	target := registry.Target(pid, nil)
	require.Same(t, target, registry.Target(pid, nil))
	_, err = target.ResolveLiveSymbols(pid, "*")
	require.ErrorContains(t, err, "not ready")
	record := make([]byte, 40)
	record[0] = javaDynamicReadyEvent
	binary.LittleEndian.PutUint32(record[4:], uint32(pid))
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	portNumber, err := strconv.Atoi(port)
	require.NoError(t, err)
	binary.LittleEndian.PutUint32(record[8:], uint32(portNumber))
	record[16] = 42
	binary.LittleEndian.PutUint64(record[32:], 1)
	require.NoError(t, registry.handleReady(&ringbuf.Record{RawSample: record}))
	require.True(t, target.LiveSymbolsChanged())
	require.False(t, target.LiveSymbolsChanged())
	var mu sync.Mutex
	var operations []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var header [33]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				if (header[0] != 42 && header[0] != 43) || !bytes.Equal(header[16:32], target.session[:]) {
					return
				}
				operation := header[32]
				mu.Lock()
				operations = append(operations, operation)
				mu.Unlock()
				switch operation {
				case javaClaimSession, javaDetachMethod:
					if operation == javaDetachMethod {
						var cookie uint64
						_ = binary.Read(conn, binary.BigEndian, &cookie)
					}
					_, _ = conn.Write([]byte{0})
				case javaListMethods:
					_, _ = conn.Write([]byte{0})
					_ = binary.Write(conn, binary.BigEndian, uint32(2))
					for _, name := range []string{"sample.Handler.write", "sample.Handler.read"} {
						_ = binary.Write(conn, binary.BigEndian, uint32(len(name)))
						_, _ = io.WriteString(conn, name)
					}
				case javaAttachMethod:
					_, _ = readJavaString(conn)
					var cookie uint64
					_ = binary.Read(conn, binary.BigEndian, &cookie)
					message := "retransformation failed"
					_, _ = conn.Write([]byte{1})
					_ = binary.Write(conn, binary.BigEndian, uint32(len(message)))
					_, _ = io.WriteString(conn, message)
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	symbols, err := target.ResolveLiveSymbols(pid, "sample.*.{read,write}")
	require.NoError(t, err)
	require.Equal(t, []string{"sample.Handler.read", "sample.Handler.write"}, symbols)
	symbols, err = target.ResolveLiveSymbols(pid, "sample.Handler.read")
	require.NoError(t, err)
	require.Len(t, symbols, 1)
	_, err = target.command(context.Background(), javaAttachMethod, symbols[0], 7)
	require.EqualError(t, err, "retransformation failed")
	_, err = target.command(context.Background(), javaDetachMethod, "", 7)
	require.NoError(t, err)
	mu.Lock()
	require.Equal(t, []byte{javaClaimSession, javaListMethods, javaAttachMethod, javaDetachMethod}, operations)
	mu.Unlock()
	binary.LittleEndian.PutUint64(record[32:], 2)
	require.NoError(t, registry.handleReady(&ringbuf.Record{RawSample: record}))
	require.True(t, target.LiveSymbolsChanged())
	_, err = target.ResolveLiveSymbols(pid, "*")
	require.NoError(t, err)
	mu.Lock()
	require.Equal(t, javaListMethods, operations[len(operations)-1])
	mu.Unlock()
	// A restarted agent advertises a new endpoint token. The target must claim
	// the new session before sending the next command so the agent can reset
	// instrumentation left by the prior OBI session.
	record[16] = 43
	binary.LittleEndian.PutUint64(record[32:], 3)
	require.NoError(t, registry.handleReady(&ringbuf.Record{RawSample: record}))
	_, err = target.ResolveLiveSymbols(pid, "sample.Handler.read")
	require.NoError(t, err)
	mu.Lock()
	require.Equal(t, []byte{javaClaimSession, javaListMethods}, operations[len(operations)-2:])
	mu.Unlock()
	registry.Remove(pid)
	_, found := registry.symbols.get(javaSymbolIdentity{pid: pid, start: target.startTime, revision: 3})
	require.False(t, found)
}

func TestJavaDynamicAnnouncementValidation(t *testing.T) {
	registry := NewDynamicRegistry(context.Background(), config.DefaultDynamicInstrumentationConfig(), ebpfcommon.NewEBPFEventContext())
	registry.Target(app.PID(os.Getpid()), nil)
	require.Error(t, registry.handleReady(&ringbuf.Record{RawSample: make([]byte, 39)}))
	record := make([]byte, 40)
	binary.LittleEndian.PutUint32(record[4:], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(record[8:], 65536)
	require.ErrorContains(t, registry.handleReady(&ringbuf.Record{RawSample: record}), "port")
	var size bytes.Buffer
	require.NoError(t, binary.Write(&size, binary.BigEndian, uint32(65537)))
	_, err := readJavaString(&size)
	require.ErrorContains(t, err, "limit")
}

func TestJavaSymbolCacheLimits(t *testing.T) {
	cfg := config.DefaultDynamicInstrumentationConfig()
	cfg.SymbolCacheEntries = 2
	cfg.SymbolCacheBytes = 100
	cfg.MaxCachedBinaryBytes = 80
	cache := newJavaSymbolCache(cfg)
	first := javaSymbolIdentity{pid: 1, start: 1, revision: 1}
	second := javaSymbolIdentity{pid: 2, start: 1, revision: 1}
	cache.put(first, []string{"first"})
	cache.put(second, []string{"second"})
	_, ok := cache.get(first)
	require.True(t, ok)
	cache.put(javaSymbolIdentity{pid: 3}, []string{"third"})
	_, ok = cache.get(second)
	require.False(t, ok, "least recently used catalog should be evicted")
	cache.put(first, []string{string(make([]byte, 81))})
	names, ok := cache.get(first)
	require.True(t, ok)
	require.Equal(t, []string{"first"}, names, "oversized catalog must not be cached")
	updated := first
	updated.revision++
	cache.put(updated, []string{"updated"})
	_, ok = cache.get(first)
	require.False(t, ok, "old class revision must be evicted")
	cache.remove(1)
	cache.remove(3)
	require.Zero(t, cache.bytes)
	cfg.MaxCachedBinaryBytes = 0
	disabled := newJavaSymbolCache(cfg)
	disabled.put(first, []string{"first"})
	_, ok = disabled.get(first)
	require.False(t, ok)
}
