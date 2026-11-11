// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
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
	"go.opentelemetry.io/obi/pkg/liveprober"
)

// The liveprober manager finds patch support by type assertion, so a signature drift would
// otherwise only show up as "target runtime does not support patches".
var _ liveprober.PatchTarget = (*DynamicTarget)(nil)

type patchRequest struct {
	operation  byte
	class      string
	method     string
	descriptor string
	value      string
	expiresAt  int64
	cookie     uint64
}

// fakePatchAgent speaks the agent's control protocol for claim, attach-patch and detach.
type fakePatchAgent struct {
	mu       sync.Mutex
	requests []patchRequest
	attachOK bool
}

func (f *fakePatchAgent) serve(t *testing.T, listener net.Listener) {
	t.Helper()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.handle(conn)
		}
	}()
}

func (f *fakePatchAgent) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var header [33]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	request := patchRequest{operation: header[32]}
	switch request.operation {
	case javaDetachMethod:
		_ = binary.Read(conn, binary.BigEndian, &request.cookie)
	case 5:
		request.class, _ = readJavaString(conn)
		request.method, _ = readJavaString(conn)
		request.descriptor, _ = readJavaString(conn)
		var action [1]byte
		_, _ = io.ReadFull(conn, action[:])
		request.value, _ = readJavaString(conn)
		_ = binary.Read(conn, binary.BigEndian, &request.expiresAt)
		_ = binary.Read(conn, binary.BigEndian, &request.cookie)
	}
	f.mu.Lock()
	f.requests = append(f.requests, request)
	ok := request.operation != 5 || f.attachOK
	f.mu.Unlock()
	if ok {
		_, _ = conn.Write([]byte{0})
		return
	}
	message := "Unknown dynamic control operation"
	_, _ = conn.Write([]byte{1})
	_ = binary.Write(conn, binary.BigEndian, uint32(len(message)))
	_, _ = io.WriteString(conn, message)
}

func (f *fakePatchAgent) operations() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var operations []byte
	for _, request := range f.requests {
		operations = append(operations, request.operation)
	}
	return operations
}

func patchTarget(t *testing.T, agent *fakePatchAgent) *DynamicTarget {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	agent.serve(t, listener)
	registry := NewDynamicRegistry(context.Background(), config.DefaultDynamicInstrumentationConfig(), ebpfcommon.NewEBPFEventContext())
	pid := app.PID(os.Getpid())
	target := registry.Target(pid, nil)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	portNumber, err := strconv.Atoi(port)
	require.NoError(t, err)
	record := make([]byte, 40)
	record[0] = javaDynamicReadyEvent
	record[16] = 42
	binary.LittleEndian.PutUint32(record[4:], uint32(pid))
	binary.LittleEndian.PutUint32(record[8:], uint32(portNumber))
	binary.LittleEndian.PutUint64(record[32:], 1)
	require.NoError(t, registry.handleReady(&ringbuf.Record{RawSample: record}))
	return target
}

func TestAttachLivePatchSendsOp5AndCloseDetaches(t *testing.T) {
	agent := &fakePatchAgent{attachOK: true}
	target := patchTarget(t, agent)
	patch := &config.PatchSpec{Class: "a.B", Method: "lookup", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;", Action: config.PatchActionReturn, Value: "none", TTL: time.Minute}
	expiresAt := time.UnixMilli(1_800_000_000_000)

	link, err := target.AttachLivePatch(target.pid, patch, expiresAt, 9)

	require.NoError(t, err)
	require.Equal(t, []byte{javaClaimSession, 5}, agent.operations())
	sent := agent.requests[1]
	require.Equal(t, patchRequest{operation: 5, class: "a.B", method: "lookup", descriptor: patch.Descriptor, value: "none", expiresAt: expiresAt.UnixMilli(), cookie: 9}, sent)
	require.NoError(t, link.Close())
	require.Equal(t, []byte{javaClaimSession, 5, javaDetachMethod}, agent.operations())
	require.Equal(t, uint64(9), agent.requests[2].cookie)
}

func TestAttachLivePatchOnAnOlderAgentFailsCleanly(t *testing.T) {
	agent := &fakePatchAgent{}
	target := patchTarget(t, agent)
	patch := &config.PatchSpec{Class: "a.B", Method: "lookup", Descriptor: "()Ljava/lang/String;", Action: config.PatchActionReturn, TTL: time.Minute}

	link, err := target.AttachLivePatch(target.pid, patch, time.Now().Add(time.Minute), 9)

	require.ErrorContains(t, err, "Unknown dynamic control operation")
	require.Nil(t, link)
}
