// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestLanguageTracersShareDynamicSpanState(t *testing.T) {
	events := ebpfcommon.NewEBPFEventContext()
	first := New(time.Minute, events, slog.Default())
	first.Register(&config.CustomSpanSpec{Name: "call", On: config.CustomSpanTarget{FunctionSpan: "main.call"}}, 1, "probe", 2)
	dispatch := func(kind obiebpf.CustomSpanEventKind) (request.Span, bool) {
		t.Helper()
		event := makeRawEvent(1, kind, 123, 100)
		event.Type = ebpfcommon.EventTypeCustomSpan
		var data bytes.Buffer
		require.NoError(t, binary.Write(&data, binary.LittleEndian, event))
		span, skip, handled, err := ebpfcommon.DispatchCustomSpan(events, &ringbuf.Record{RawSample: data.Bytes()})
		require.NoError(t, err)
		require.True(t, handled)
		return span, skip
	}
	_, skip := dispatch(obiebpf.CustomSpanKindStart)
	require.True(t, skip)

	// Loading another language tracer must retain definitions and incomplete calls.
	second := New(time.Minute, events, slog.Default())
	span, skip := dispatch(obiebpf.CustomSpanKindEnd)
	require.False(t, skip)
	require.Equal(t, "call", span.Method)

	_, skip = dispatch(obiebpf.CustomSpanKindStart)
	require.True(t, skip)
	second.Remove(1)
	_, skip = dispatch(obiebpf.CustomSpanKindEnd)
	require.True(t, skip, "detached probes must be removed from every reader")
}

func TestJavaSpansPairAcrossCarrierThreads(t *testing.T) {
	runtime := New(time.Minute, nil, slog.Default())
	runtime.RegisterJava(&config.CustomSpanSpec{Name: "work", On: config.CustomSpanTarget{FunctionSpan: "example.Service.work"}}, 9, "java", 1)
	start := makeRawEvent(9, obiebpf.CustomSpanKindStart, 123, 100)
	start.Type = ebpfcommon.EventTypeCustomSpan
	start.PairKind = 3
	start.GPtr = 101
	start.GlobalTid = 10
	start.ID[0] = 3
	start.TraceID[0] = 1
	start.SpanID[0] = 2
	start.HasTraceCtx = 1
	start.ArgCnt = 2
	start.ArgKind[0] = uint8(obiebpf.CustomSpanArgStr)
	start.ArgKind[1] = uint8(obiebpf.CustomSpanArgStr)
	copy(start.ArgStr[0][:], "42")
	copy(start.ArgStr[1][:], "hello")
	dispatch := func(event *CustomSpanRawEvent) (request.Span, bool) {
		t.Helper()
		var data bytes.Buffer
		require.NoError(t, binary.Write(&data, binary.LittleEndian, event))
		span, ready, handled, err := runtime.HandleRecord(&ringbuf.Record{RawSample: data.Bytes()})
		require.NoError(t, err)
		require.True(t, handled)
		return span, ready
	}
	_, ready := dispatch(&start)
	require.False(t, ready)
	end := start
	end.Kind = uint8(obiebpf.CustomSpanKindEnd)
	end.GlobalTid = 20
	end.Timestamp += 100
	end.ArgCnt = 1
	end.ArgKind[1] = 0
	end.ArgStr = [customSpanMaxArgs][customSpanStrLen]byte{}
	copy(end.ArgStr[0][:], "43")
	span, ready := dispatch(&end)
	require.True(t, ready)
	require.Equal(t, uint8(1), span.TraceID[0])
	require.Equal(t, uint8(2), span.ParentSpanID[0])
	require.Equal(t, uint8(3), span.SpanID[0])
	require.Equal(t, map[string]string{"arg0": "42", "arg1": "hello", "return0": "43", "probe.id": "java", "probe.generation": "1"}, span.CustomSpan.Attrs)
	runtime.Remove(9)
	_, ready = dispatch(&start)
	require.False(t, ready)
	require.Zero(t, runtime.pairer.PendingLen())
}
