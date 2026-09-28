// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
)

func makeRawEvent(cookie uint64, kind obiebpf.CustomSpanEventKind, arg0 uint64, ts uint64) CustomSpanRawEvent {
	return CustomSpanRawEvent{
		Type:      21,
		Kind:      uint8(kind),
		ArgCnt:    1,
		Cookie:    cookie,
		Timestamp: ts,
		GlobalPid: 100,
		ArgKind:   [customSpanMaxArgs]uint8{uint8(obiebpf.CustomSpanArgInt)},
		ArgInt:    [customSpanMaxArgs]uint64{arg0},
	}
}

func TestCustomSpanRawEvent_LayoutRoundtrip(t *testing.T) {
	src := CustomSpanRawEvent{
		Type:        21,
		Kind:        2,
		ArgCnt:      4,
		HasTraceCtx: 1,
		Cookie:      0xABCD1234,
		Timestamp:   123456789,
		GlobalPid:   1000,
		GlobalTid:   1000,
		NsPid:       7,
		NsTid:       7,
		PidNsID:     42,
		TraceID:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:      [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		ArgKind:     [customSpanMaxArgs]uint8{1, 2},
		ArgStrLen:   [customSpanMaxArgs]uint16{0, 6},
		ArgInt:      [customSpanMaxArgs]uint64{0xDEADBEEF},
	}
	copy(src.ArgStr[1][:], []byte("hello\x00"))

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &src))

	got, err := DecodeCustomSpanEvent(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, src, *got)
}

func TestCustomSpanBuilder_PairingMatches(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)

	def := NewCustomSpanDef(&config.CustomSpanSpec{
		Name: "order.process",
		On:   config.CustomSpanTarget{USDTSpan: "myapp:order"},
		Attrs: map[string]config.CustomSpanAttr{
			"order_id": {Arg: 0, Type: config.CustomSpanAttrU64},
		},
	}, 7)
	reg.Register(def)

	start := makeRawEvent(7, obiebpf.CustomSpanKindStart, 999, 1000)
	span, ready, err := b.Build(&start)
	require.NoError(t, err)
	require.False(t, ready)
	require.Equal(t, request.Span{}, span)
	assert.Equal(t, 1, pairer.PendingLen())

	end := makeRawEvent(7, obiebpf.CustomSpanKindEnd, 999, 2000)
	span, ready, err = b.Build(&end)
	require.NoError(t, err)
	require.True(t, ready)
	assert.Equal(t, request.EventTypeCustomSpan, span.Type)
	assert.Equal(t, "order.process", span.Method)
	assert.Equal(t, int64(1000), span.Start)
	assert.Equal(t, int64(2000), span.End)
	require.NotNil(t, span.CustomSpan)
	assert.Equal(t, "999", span.CustomSpan.Attrs["order_id"])
	assert.Equal(t, 0, pairer.PendingLen())
}

func TestCustomSpanBuilder_PairingMismatchedKeyIsOrphan(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)

	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{
		Name: "n", On: config.CustomSpanTarget{USDTSpan: "a:b"},
	}, 1))

	start := makeRawEvent(1, obiebpf.CustomSpanKindStart, 111, 1000)
	_, ready, err := b.Build(&start)
	require.NoError(t, err)
	require.False(t, ready)

	end := makeRawEvent(1, obiebpf.CustomSpanKindEnd, 222, 2000)
	span, ready, err := b.Build(&end)
	require.NoError(t, err)
	require.False(t, ready, "mismatched arg0 must not emit a span")
	assert.Equal(t, request.Span{}, span)
	assert.Equal(t, 1, pairer.PendingLen(), "orphan start must remain pending until TTL")
}

func TestCustomSpanBuilder_SingleShotEmitsImmediately(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)

	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{
		Name: "cache.hit",
		On:   config.CustomSpanTarget{USDTNoRet: "myapp:cache_hit"},
		Attrs: map[string]config.CustomSpanAttr{
			"key": {Arg: 0, Type: config.CustomSpanAttrString},
		},
	}, 42))

	ev := makeRawEvent(42, obiebpf.CustomSpanKindSingle, 0, 5000)
	ev.ArgKind[0] = uint8(obiebpf.CustomSpanArgStr)
	copy(ev.ArgStr[0][:], []byte("user:1234\x00"))
	ev.ArgStrLen[0] = 10

	span, ready, err := b.Build(&ev)
	require.NoError(t, err)
	require.True(t, ready)
	assert.Equal(t, request.EventTypeCustomSpan, span.Type)
	assert.Equal(t, int64(5000), span.Start)
	assert.Equal(t, int64(5000), span.End)
	assert.Equal(t, "user:1234", span.CustomSpan.Attrs["key"])
}

func TestCustomSpanBuilder_UnknownCookieIsDropped(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)

	ev := makeRawEvent(999, obiebpf.CustomSpanKindStart, 1, 1)
	_, ready, err := b.Build(&ev)
	require.NoError(t, err)
	require.False(t, ready)
	assert.Equal(t, 0, pairer.PendingLen())
}

func TestCustomSpanBuilder_PairingByDistinctArg0(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{
		Name: "n", On: config.CustomSpanTarget{USDTSpan: "a:b"},
	}, 1))

	for _, arg0 := range []uint64{10, 20} {
		s := makeRawEvent(1, obiebpf.CustomSpanKindStart, arg0, 1000+arg0)
		_, ready, _ := b.Build(&s)
		require.False(t, ready)
	}
	assert.Equal(t, 2, pairer.PendingLen())

	end20 := makeRawEvent(1, obiebpf.CustomSpanKindEnd, 20, 3000)
	span, ready, _ := b.Build(&end20)
	require.True(t, ready)
	assert.Equal(t, int64(1020), span.Start)
	assert.Equal(t, 1, pairer.PendingLen())

	end10 := makeRawEvent(1, obiebpf.CustomSpanKindEnd, 10, 4000)
	span, ready, _ = b.Build(&end10)
	require.True(t, ready)
	assert.Equal(t, int64(1010), span.Start)
	assert.Equal(t, 0, pairer.PendingLen())
}

func TestCustomSpanPairer_EvictsExpired(t *testing.T) {
	pairer := NewCustomSpanPairer(100 * time.Millisecond)
	frozen := time.Unix(0, 0)
	pairer.now = func() time.Time { return frozen }

	pairer.putStart(customSpanPairKey{PID: 1, Cookie: 1, Key: 1}, customSpanPending{StartedAt: frozen})
	pairer.putStart(customSpanPairKey{PID: 1, Cookie: 1, Key: 2}, customSpanPending{StartedAt: frozen})

	frozen = frozen.Add(50 * time.Millisecond)
	assert.Equal(t, 0, pairer.EvictExpired())

	frozen = frozen.Add(200 * time.Millisecond)
	assert.Equal(t, 2, pairer.EvictExpired())
	assert.Equal(t, 0, pairer.PendingLen())
}

func TestCustomSpanBuilder_TraceCtxInheritance(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{
		Name: "n", On: config.CustomSpanTarget{USDTSpan: "a:b"},
	}, 1))

	start := makeRawEvent(1, obiebpf.CustomSpanKindStart, 5, 1000)
	start.HasTraceCtx = 1
	for i := range start.TraceID {
		start.TraceID[i] = byte(i + 1)
	}
	for i := range start.SpanID {
		start.SpanID[i] = byte(0x80 + i)
	}
	_, _, _ = b.Build(&start)

	end := makeRawEvent(1, obiebpf.CustomSpanKindEnd, 5, 2000)
	span, ready, _ := b.Build(&end)
	require.True(t, ready)
	assert.NotEqual(t, [16]byte{}, [16]byte(span.TraceID))
	assert.Equal(t, byte(1), span.TraceID[0])
	assert.Equal(t, byte(0x80), span.ParentSpanID[0])
}

func TestCustomSpanBuilder_EndOverridesAttr(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	b := NewCustomSpanBuilder(reg, pairer)

	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{
		Name: "op",
		On:   config.CustomSpanTarget{USDTSpan: "myapp:op"},
		Attrs: map[string]config.CustomSpanAttr{
			"id":     {Arg: 0, Type: config.CustomSpanAttrU64},
			"status": {Arg: 1, Type: config.CustomSpanAttrI32},
		},
	}, 11))

	start := makeRawEvent(11, obiebpf.CustomSpanKindStart, 7, 1000)
	start.ArgCnt = 2
	start.ArgKind[1] = uint8(obiebpf.CustomSpanArgInt)
	start.ArgInt[1] = 0
	_, _, _ = b.Build(&start)

	end := makeRawEvent(11, obiebpf.CustomSpanKindEnd, 7, 2000)
	end.ArgCnt = 2
	end.ArgKind[1] = uint8(obiebpf.CustomSpanArgInt)
	var neg32 int32 = -13
	end.ArgInt[1] = uint64(uint32(neg32))
	span, ready, _ := b.Build(&end)
	require.True(t, ready)
	assert.Equal(t, "7", span.CustomSpan.Attrs["id"])
	assert.Equal(t, "-13", span.CustomSpan.Attrs["status"])
}

func TestDynamicSpansNestRecursivelyAcrossThreadChanges(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	builder := NewCustomSpanBuilder(reg, pairer)
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{Name: "recursive", On: config.CustomSpanTarget{FunctionSpan: "main.recurse"}}, 1))
	outer := makeRawEvent(1, obiebpf.CustomSpanKindStart, 0, 100)
	outer.PairKind = obiebpf.ObiUSDTPairG()
	outer.GPtr = 123
	outer.GlobalTid = 10
	outer.HasTraceCtx = 1
	outer.TraceID = [16]byte{1}
	outer.SpanID = [8]byte{2}
	_, ready, err := builder.Build(&outer)
	require.NoError(t, err)
	require.False(t, ready)
	inner := outer
	inner.Timestamp = 110
	inner.GlobalTid = 20
	_, ready, err = builder.Build(&inner)
	require.NoError(t, err)
	require.False(t, ready)
	inner.Kind = uint8(obiebpf.CustomSpanKindEnd)
	inner.Timestamp = 120
	child, ready, err := builder.Build(&inner)
	require.NoError(t, err)
	require.True(t, ready)
	outer.Kind = uint8(obiebpf.CustomSpanKindEnd)
	outer.Timestamp = 130
	parent, ready, err := builder.Build(&outer)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, parent.SpanID, child.ParentSpanID)
	require.Equal(t, parent.TraceID, child.TraceID)
	require.Equal(t, outer.SpanID, [8]byte(parent.ParentSpanID))
	require.Equal(t, 0, pairer.PendingLen())
}

func TestDynamicSpanPrefersNewSDKParent(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	builder := NewCustomSpanBuilder(reg, pairer)
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{Name: "outer", On: config.CustomSpanTarget{FunctionSpan: "main.outer"}}, 1))
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{Name: "inner", On: config.CustomSpanTarget{FunctionSpan: "main.inner"}}, 2))
	event := makeRawEvent(1, obiebpf.CustomSpanKindStart, 0, 100)
	event.PairKind = obiebpf.ObiUSDTPairG()
	event.GPtr = 123
	event.HasTraceCtx = 1
	event.TraceID = [16]byte{1}
	event.SpanID = [8]byte{2}
	_, _, err := builder.Build(&event)
	require.NoError(t, err)
	event.Cookie = 2
	event.SpanID = [8]byte{3}
	_, _, err = builder.Build(&event)
	require.NoError(t, err)
	event.Kind = uint8(obiebpf.CustomSpanKindEnd)
	child, ready, err := builder.Build(&event)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, event.SpanID, [8]byte(child.ParentSpanID))
	pairer.Remove(1)
	require.Zero(t, pairer.PendingLen())
}

func TestGoStackGrowthDoesNotCreatePhantomParent(t *testing.T) {
	reg := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(time.Minute)
	builder := NewCustomSpanBuilder(reg, pairer)
	reg.Register(NewCustomSpanDef(&config.CustomSpanSpec{Name: "call", On: config.CustomSpanTarget{FunctionSpan: "main.call"}}, 1))
	entry := makeRawEvent(1, obiebpf.CustomSpanKindStart, 0, 100)
	entry.PairKind = obiebpf.ObiUSDTPairG()
	entry.GPtr = 123
	entry.StackOffset = 64
	entry.HasTraceCtx = 1
	entry.TraceID = [16]byte{1}
	entry.SpanID = [8]byte{2}
	_, _, err := builder.Build(&entry)
	require.NoError(t, err)
	entry.Timestamp = 110
	_, _, err = builder.Build(&entry)
	require.NoError(t, err)
	require.Equal(t, 1, pairer.PendingLen())
	recursive := entry
	recursive.Timestamp = 120
	recursive.StackOffset = 128
	_, _, err = builder.Build(&recursive)
	require.NoError(t, err)
	require.Equal(t, 2, pairer.PendingLen())
	recursive.Kind = uint8(obiebpf.CustomSpanKindEnd)
	child, ready, err := builder.Build(&recursive)
	require.NoError(t, err)
	require.True(t, ready)
	entry.Kind = uint8(obiebpf.CustomSpanKindEnd)
	parent, ready, err := builder.Build(&entry)
	require.NoError(t, err)
	require.True(t, ready)
	require.Equal(t, entry.SpanID, [8]byte(parent.ParentSpanID))
	require.Equal(t, parent.SpanID, child.ParentSpanID)
	require.Zero(t, pairer.PendingLen())
}
