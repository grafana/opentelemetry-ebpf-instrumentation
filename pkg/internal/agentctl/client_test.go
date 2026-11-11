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
	}
	var want bytes.Buffer
	for _, text := range []string{patch.Class, patch.Method, patch.Descriptor} {
		writeString(&want, text)
	}
	want.WriteByte(1)
	writeString(&want, patch.Value)
	_ = binary.Write(&want, binary.BigEndian, int64(1_800_000_000_123))
	_ = binary.Write(&want, binary.BigEndian, uint64(77))
	var header [33]byte
	port, payload := serveOnce(t, []byte{0}, &header, want.Len())
	token, session := [16]byte{1}, [16]byte{2}

	err := ExchangePatch(context.Background(), app.PID(os.Getpid()), port, token, session, patch, 77)

	require.NoError(t, err)
	require.Equal(t, token[:], header[:16])
	require.Equal(t, session[:], header[16:32])
	require.Equal(t, AttachPatch, header[32])
	require.Equal(t, want.Bytes(), <-payload)
}

func TestExchangePatchReturnsAgentError(t *testing.T) {
	var reply bytes.Buffer
	reply.WriteByte(1)
	writeString(&reply, "Unknown dynamic control operation")
	var header [33]byte
	port, _ := serveOnce(t, reply.Bytes(), &header, 0)

	err := ExchangePatch(context.Background(), app.PID(os.Getpid()), port, [16]byte{}, [16]byte{}, Patch{ExpiresAt: time.Now()}, 1)

	require.EqualError(t, err, "Unknown dynamic control operation")
}
