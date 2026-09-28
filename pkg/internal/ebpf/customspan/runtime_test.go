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
