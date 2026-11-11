// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentctl

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// serveOnce accepts one connection, returns everything the client sent after the 33-byte header,
// and replies with reply.
func serveOnce(t *testing.T, reply []byte, header *[33]byte, payloadSize int) (port uint32, payload <-chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.ReadFull(conn, header[:])
		body := make([]byte, payloadSize)
		_, _ = io.ReadFull(conn, body)
		received <- body
		_, _ = conn.Write(reply)
	}()
	return uint32(listener.Addr().(*net.TCPAddr).Port), received
}

func TestExchangePatchSendsAttachPatchWireFormat(t *testing.T) {
	patch := Patch{
		Class:      "a.B",
		Method:     "lookup",
		Descriptor: "(Ljava/lang/String;)Ljava/lang/String;",
		Value:      "none",
		ExpiresAt:  time.UnixMilli(1_800_000_000_123),

		RequireIdentity: true,
		Loader:          "loader:3",
		ArtifactSHA256:  strings.Repeat("a", 64),
		Fingerprint:     strings.Repeat("b", 64),
		Observe:         true,
		Predicate:       &Predicate{Argument: 1, Contains: "canary.test"},
	}
	var want bytes.Buffer
	for _, text := range []string{patch.Class, patch.Method, patch.Descriptor} {
		writeString(&want, text)
	}
	want.WriteByte(1)
	writeString(&want, patch.Value)
	_ = binary.Write(&want, binary.BigEndian, int64(1_800_000_000_123))
	_ = binary.Write(&want, binary.BigEndian, uint64(77))
	want.WriteByte(1)
	for _, text := range []string{patch.Loader, patch.ArtifactSHA256, patch.Fingerprint} {
		writeString(&want, text)
	}
	want.WriteByte(1) // observe
	_ = binary.Write(&want, binary.BigEndian, int32(1))
	writeString(&want, "canary.test")
	// Reply: ok, then the resolved evidence (loader, artifact, fingerprint).
	reply := bytes.NewBuffer([]byte{0})
	for _, text := range []string{"loader:3", strings.Repeat("a", 64), strings.Repeat("c", 64)} {
		writeString(reply, text)
	}
	var header [33]byte
	port, payload := serveOnce(t, reply.Bytes(), &header, want.Len())
	token, session := [16]byte{1}, [16]byte{2}

	evidence, err := ExchangePatch(context.Background(), app.PID(os.Getpid()), port, token, session, patch, 77)

	require.NoError(t, err)
	require.Equal(t, PatchEvidence{Loader: "loader:3", ArtifactSHA256: strings.Repeat("a", 64), Fingerprint: strings.Repeat("c", 64)}, evidence)
	require.Equal(t, token[:], header[:16])
	require.Equal(t, session[:], header[16:32])
	require.Equal(t, AttachPatch, header[32])
	require.Equal(t, want.Bytes(), <-payload)
}

func TestExchangePatchWithoutAPredicateSendsNoArgument(t *testing.T) {
	patch := Patch{Class: "a.B", Method: "m", Descriptor: "()Ljava/lang/String;", ExpiresAt: time.UnixMilli(5)}
	var want bytes.Buffer
	for _, text := range []string{"a.B", "m", "()Ljava/lang/String;"} {
		writeString(&want, text)
	}
	want.WriteByte(1)
	writeString(&want, "")
	_ = binary.Write(&want, binary.BigEndian, int64(5))
	_ = binary.Write(&want, binary.BigEndian, uint64(1))
	want.WriteByte(0)
	for range 3 {
		writeString(&want, "")
	}
	want.WriteByte(0) // enforce
	_ = binary.Write(&want, binary.BigEndian, int32(-1))
	writeString(&want, "")
	reply := bytes.NewBuffer([]byte{0})
	for range 3 {
		writeString(reply, "")
	}
	var header [33]byte
	port, payload := serveOnce(t, reply.Bytes(), &header, want.Len())

	_, err := ExchangePatch(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{}, patch, 1)

	require.NoError(t, err)
	require.Equal(t, want.Bytes(), <-payload)
}

func countersReply(now int64, rows ...[]any) []byte {
	var reply bytes.Buffer
	reply.WriteByte(0)
	_ = binary.Write(&reply, binary.BigEndian, now)
	_ = binary.Write(&reply, binary.BigEndian, uint32(len(rows)))
	for _, row := range rows {
		for _, field := range row {
			_ = binary.Write(&reply, binary.BigEndian, field)
		}
	}
	return reply.Bytes()
}

func TestExchangeCountersReadsEveryObservingPatch(t *testing.T) {
	reply := countersReply(1_700_000_005_000,
		// cookie, calls, hits, hasPredicate, first, last, since
		[]any{uint64(7), uint64(12), uint64(2), uint8(1), int64(1_700_000_001_000), int64(1_700_000_004_000), int64(1_700_000_000_000)},
		[]any{uint64(8), uint64(0), uint64(0), uint8(0), int64(0), int64(0), int64(1_700_000_002_000)},
	)
	var header [33]byte
	port, _ := serveOnce(t, reply, &header, 0)
	token, session := [16]byte{1}, [16]byte{2}

	counters, err := ExchangeCounters(context.Background(), app.PID(os.Getpid()), port, token, session)

	require.NoError(t, err)
	require.Equal(t, ReadPatchCounters, header[32])
	require.Equal(t, time.UnixMilli(1_700_000_005_000), counters.Now)
	require.Len(t, counters.Patches, 2)
	require.Equal(t, PatchCounters{
		Cookie: 7, Calls: 12, PredicateHits: 2, HasPredicate: true,
		FirstSeen: time.UnixMilli(1_700_000_001_000), LastSeen: time.UnixMilli(1_700_000_004_000),
		Since: time.UnixMilli(1_700_000_000_000),
	}, counters.Patches[0])
	// Never called: a known zero with no first/last seen.
	require.Equal(t, PatchCounters{Cookie: 8, Since: time.UnixMilli(1_700_000_002_000)}, counters.Patches[1])
	require.True(t, counters.Patches[1].FirstSeen.IsZero())
}

func TestExchangeCountersRejectsTruncatedAndOversizedReplies(t *testing.T) {
	truncated := countersReply(1, []any{uint64(7), uint64(1)})
	var header [33]byte
	port, _ := serveOnce(t, truncated, &header, 0)
	_, err := ExchangeCounters(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{})
	require.ErrorContains(t, err, "reading counters")

	var huge bytes.Buffer
	huge.WriteByte(0)
	_ = binary.Write(&huge, binary.BigEndian, int64(1))
	_ = binary.Write(&huge, binary.BigEndian, uint32(1_000_000))
	port, _ = serveOnce(t, huge.Bytes(), &header, 0)
	_, err = ExchangeCounters(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{})
	require.ErrorContains(t, err, "exceeds limit")
}

func TestExchangeCountersSurfacesAnAgentError(t *testing.T) {
	var reply bytes.Buffer
	reply.WriteByte(1)
	writeString(&reply, "Unknown dynamic control operation")
	var header [33]byte
	port, _ := serveOnce(t, reply.Bytes(), &header, 0)

	_, err := ExchangeCounters(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{})

	require.EqualError(t, err, "Unknown dynamic control operation")
}

func TestExchangePatchReturnsAgentError(t *testing.T) {
	var reply bytes.Buffer
	reply.WriteByte(1)
	writeString(&reply, "Unknown dynamic control operation")
	var header [33]byte
	port, _ := serveOnce(t, reply.Bytes(), &header, 0)

	evidence, err := ExchangePatch(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{}, Patch{ExpiresAt: time.Now()}, 1)

	require.EqualError(t, err, "Unknown dynamic control operation")
	require.Equal(t, PatchEvidence{}, evidence)
}

func TestExchangePatchSurfacesARefusalReason(t *testing.T) {
	var reply bytes.Buffer
	reply.WriteByte(1)
	writeString(&reply, "PatchRefusal AMBIGUOUS_LOADER: 2 loaders define a.B.lookup")
	var header [33]byte
	port, _ := serveOnce(t, reply.Bytes(), &header, 0)

	_, err := ExchangePatch(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{}, Patch{ExpiresAt: time.Now()}, 1)

	require.ErrorContains(t, err, "PatchRefusal AMBIGUOUS_LOADER:")
}
