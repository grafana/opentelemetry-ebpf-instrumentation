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
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestNodeDynamicDecoderAndRemoval(t *testing.T) {
	events := ebpfcommon.NewEBPFEventContext()
	runtime := New(time.Minute, events, slog.Default())
	runtime.RegisterStringArgs(&config.CustomSpanSpec{Name: "inner"}, 17, "rule", 3)
	event := ebpfcommon.BpfNodeDynamicSpanEventT{Cookie: 17, TraceFlags: 1}
	event.Span.Type = ebpfcommon.EventTypeNodeDynamicSpan
	event.Span.HasParentCtx = 1
	event.Span.EndKtime = 10000
	event.Span.ParentTraceId[0] = 12
	event.Span.ParentSpanId[0] = 34
	event.Span.Pid.HostPid = 123
	payload := `{"name":"dynamic","sid":"abcdef0123456789","tid":"11111111111111111111111111111111","durNs":"100","attrs":{"arg0":"a","return0":"b"}}`
	copy(event.Span.Payload[:], payload)
	event.Span.PayloadLen = uint32(len(payload))
	var encoded bytes.Buffer
	require.NoError(t, binary.Write(&encoded, binary.LittleEndian, &event))
	record := &ringbuf.Record{RawSample: encoded.Bytes()}
	span, skip, handled, err := ebpfcommon.DispatchCustomSpan(events, record)
	require.NoError(t, err)
	require.True(t, handled)
	require.False(t, skip)
	require.Equal(t, request.EventTypeCustomSpan, span.Type)
	require.Equal(t, uint8(1), span.TraceFlags)
	require.Equal(t, byte(12), span.TraceID[0])
	require.Equal(t, byte(34), span.ParentSpanID[0])
	require.Equal(t, "inner", span.Method)
	require.Equal(t, map[string]string{"arg0": "a", "return0": "b", "probe.id": "rule", "probe.generation": "3"}, span.CustomSpan.Attrs)
	runtime.Remove(17)
	_, skip, handled, err = ebpfcommon.DispatchCustomSpan(events, record)
	require.NoError(t, err)
	require.True(t, handled)
	require.True(t, skip)
}
