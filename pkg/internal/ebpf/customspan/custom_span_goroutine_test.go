// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func TestDynamicGoroutineCapturesParentAtCreation(t *testing.T) {
	for _, test := range []struct {
		name         string
		intermediary bool
	}{
		{name: "direct"},
		{name: "untraced intermediary", intermediary: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reg := NewCustomSpanRegistry()
			pairer := NewCustomSpanPairer(time.Minute)
			builder := NewCustomSpanBuilder(reg, pairer)
			reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{Name: "call", On: config.CustomSpanTarget{FunctionSpan: "main.call"}}, 1))
			entry := makeRawEvent(1, obiebpf.CustomSpanKindStart, 0, 100)
			entry.PairKind, entry.GPtr = obiebpf.ObiUSDTPairG(), 123
			_, _, err := builder.Build(&entry)
			require.NoError(t, err)
			fork := customSpanGoroutineEvent{Kind: customSpanGoroutineStart, PID: entry.GlobalPid, Parent: entry.GPtr, Goroutine: 456}
			pairer.observeGoroutine(fork)
			end := entry
			end.Kind = uint8(obiebpf.CustomSpanKindEnd)
			parent, ready, err := builder.Build(&end)
			require.NoError(t, err)
			require.True(t, ready)
			// The creating goroutine starts unrelated work before its child runs.
			_, _, err = builder.Build(&entry)
			require.NoError(t, err)
			if test.intermediary {
				fork.Parent, fork.Goroutine = fork.Goroutine, 789
				pairer.observeGoroutine(fork)
			}
			childEntry := entry
			childEntry.GPtr = fork.Goroutine
			_, _, err = builder.Build(&childEntry)
			require.NoError(t, err)
			childEntry.Kind = uint8(obiebpf.CustomSpanKindEnd)
			child, ready, err := builder.Build(&childEntry)
			require.NoError(t, err)
			require.True(t, ready)
			require.Equal(t, parent.SpanID, child.ParentSpanID)
			require.Equal(t, parent.TraceID, child.TraceID)
		})
	}
}

func TestDynamicGoroutineNewSDKContextTakesPrecedence(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	builder := NewCustomSpanBuilder(reg, pairer)
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{Name: "call", On: config.CustomSpanTarget{FunctionSpan: "main.call"}}, 1))
	entry := makeRawEvent(1, obiebpf.CustomSpanKindStart, 0, 100)
	entry.PairKind, entry.GPtr = obiebpf.ObiUSDTPairG(), 123
	entry.HasTraceCtx, entry.TraceID, entry.SpanID = 1, [16]byte{1}, [8]byte{2}
	_, _, err := builder.Build(&entry)
	require.NoError(t, err)
	fork := customSpanGoroutineEvent{Kind: customSpanGoroutineStart, PID: entry.GlobalPid, Parent: entry.GPtr, Goroutine: 456, TraceID: entry.TraceID, SpanID: trace.SpanID{3}}
	pairer.observeGoroutine(fork)
	child := entry
	child.GPtr, child.HasTraceCtx, child.TraceID, child.SpanID = fork.Goroutine, 0, [16]byte{}, [8]byte{}
	_, _, err = builder.Build(&child)
	require.NoError(t, err)
	child.Kind = uint8(obiebpf.CustomSpanKindEnd)
	span, ready, err := builder.Build(&child)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, fork.SpanID, span.ParentSpanID)

	child.Kind, child.HasTraceCtx, child.TraceID, child.SpanID = uint8(obiebpf.CustomSpanKindStart), 1, fork.TraceID, [8]byte{4}
	_, _, err = builder.Build(&child)
	require.NoError(t, err)
	child.Kind = uint8(obiebpf.CustomSpanKindEnd)
	span, ready, err = builder.Build(&child)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, trace.SpanID(child.SpanID), span.ParentSpanID)
}

func TestDynamicGoroutineContextLifetime(t *testing.T) {
	pairer := NewCustomSpanPairer(time.Minute)
	now := time.Now()
	pairer.now = func() time.Time { return now }
	fork := customSpanGoroutineEvent{Kind: customSpanGoroutineStart, PID: 1, Parent: 123, Goroutine: 456, TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}}
	key := customSpanPairKey{Kind: obiebpf.ObiUSDTPairG(), PID: fork.PID, Key: fork.Goroutine}
	pairer.observeGoroutine(fork)
	require.True(t, pairer.parents.Contains(key))
	reused := fork
	reused.Parent, reused.TraceID, reused.SpanID = 999, trace.TraceID{}, trace.SpanID{}
	pairer.observeGoroutine(reused)
	require.False(t, pairer.parents.Contains(key), "goroutine reuse must clear old context even after a lost exit event")

	pairer.observeGoroutine(fork)
	pairer.putStart(key, customSpanPending{ID: trace.SpanID{3}, StartedAt: now})
	exit := fork
	exit.Kind = customSpanGoroutineEnd
	pairer.observeGoroutine(exit)
	require.Zero(t, pairer.parents.Len())
	require.Zero(t, pairer.PendingLen())

	pairer.observeGoroutine(fork)
	now = now.Add(2 * time.Minute)
	require.Equal(t, 1, pairer.EvictExpired())
	require.Zero(t, pairer.parents.Len())

	pairer.parents.Resize(2)
	for i := range uint64(3) {
		fork.Goroutine = 456 + i
		pairer.observeGoroutine(fork)
	}
	require.Equal(t, 2, pairer.parents.Len())
	require.False(t, pairer.parents.Contains(key))
}

func TestDynamicGoroutineRecordDispatch(t *testing.T) {
	event := customSpanGoroutineEvent{Type: ebpfcommon.EventTypeGoDynamicGoroutine, Kind: customSpanGoroutineStart, PID: 100, Goroutine: 456, Parent: 123, TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}}
	var data bytes.Buffer
	require.NoError(t, binary.Write(&data, binary.LittleEndian, event))
	decoded, err := decodeCustomSpanGoroutineEvent(data.Bytes())
	require.NoError(t, err)
	require.Equal(t, event, decoded)

	pairer := NewCustomSpanPairer(time.Minute)
	runtime := &Runtime{pairer: pairer}
	ctx := &ebpfcommon.EBPFEventContext{CustomSpanHandler: runtime.HandleRecord}
	_, skip, handled, err := ebpfcommon.DispatchCustomSpan(ctx, &ringbuf.Record{RawSample: data.Bytes()})
	require.NoError(t, err)
	require.True(t, skip, "goroutine metadata must not emit a span")
	require.True(t, handled)
	key := customSpanPairKey{Kind: obiebpf.ObiUSDTPairG(), PID: event.PID, Key: event.Goroutine}
	require.True(t, pairer.parents.Contains(key))

	_, skip, handled, err = ebpfcommon.DispatchCustomSpan(ctx, &ringbuf.Record{RawSample: data.Bytes()[:data.Len()-1]})
	require.Error(t, err)
	require.True(t, skip)
	require.True(t, handled)
}
