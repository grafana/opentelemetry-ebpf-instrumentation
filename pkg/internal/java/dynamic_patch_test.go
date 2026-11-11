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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
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
	strict     bool
	loader     string
	artifact   string
	print      string
	observe    bool
	predicate  int32
	contains   string
}

// fakePatchAgent speaks the agent's control protocol for claim, attach-patch and detach.
type fakePatchAgent struct {
	mu       sync.Mutex
	requests []patchRequest
	attachOK bool
	// counters is the body (after the status byte) of the reply to the counters operation.
	counters []byte
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
		var strict [1]byte
		_, _ = io.ReadFull(conn, strict[:])
		request.strict = strict[0] != 0
		request.loader, _ = readJavaString(conn)
		request.artifact, _ = readJavaString(conn)
		request.print, _ = readJavaString(conn)
		var observe [1]byte
		_, _ = io.ReadFull(conn, observe[:])
		request.observe = observe[0] != 0
		_ = binary.Read(conn, binary.BigEndian, &request.predicate)
		request.contains, _ = readJavaString(conn)
	}
	f.mu.Lock()
	f.requests = append(f.requests, request)
	ok := request.operation != 5 || f.attachOK
	f.mu.Unlock()
	if ok {
		_, _ = conn.Write([]byte{0})
		if request.operation == agentctl.ReadPatchCounters {
			_, _ = conn.Write(f.counters)
		}
		if request.operation == 5 {
			for _, text := range []string{"loader:1", strings.Repeat("a", 64), strings.Repeat("b", 64)} {
				_ = binary.Write(conn, binary.BigEndian, uint32(len(text)))
				_, _ = io.WriteString(conn, text)
			}
		}
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
	patch := &config.PatchSpec{
		Class: "a.B", Method: "lookup", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;", Action: config.PatchActionReturn, Value: "none", TTL: time.Minute,
		Loader: "loader:1", ArtifactSHA256: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), RequireIdentity: true,
	}
	expiresAt := time.UnixMilli(1_800_000_000_000)

	link, evidence, err := target.AttachLivePatch(target.pid, patch, expiresAt, 9)

	require.NoError(t, err)
	require.Equal(t, agentctl.PatchEvidence{Loader: "loader:1", ArtifactSHA256: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64)}, evidence)
	require.Equal(t, []byte{javaClaimSession, 5}, agent.operations())
	sent := agent.requests[1]
	require.Equal(t, patchRequest{
		operation: 5, class: "a.B", method: "lookup", descriptor: patch.Descriptor, value: "none", expiresAt: expiresAt.UnixMilli(), cookie: 9,
		strict: true, loader: "loader:1", artifact: strings.Repeat("a", 64), print: strings.Repeat("b", 64),
		predicate: -1,
	}, sent)
	require.NoError(t, link.Close())
	require.Equal(t, []byte{javaClaimSession, 5, javaDetachMethod}, agent.operations())
	require.Equal(t, uint64(9), agent.requests[2].cookie)
}

func TestAttachLivePatchInObserveModeSendsTheModeAndPredicate(t *testing.T) {
	agent := &fakePatchAgent{attachOK: true}
	target := patchTarget(t, agent)
	patch := &config.PatchSpec{
		Class: "a.B", Method: "lookup", Descriptor: "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;", TTL: time.Minute,
		Mode: config.PatchModeObserve, Predicate: &config.PatchPredicate{Argument: 1, Contains: "canary.test"},
	}

	_, _, err := target.AttachLivePatch(target.pid, patch, time.UnixMilli(1_800_000_000_000), 4)

	require.NoError(t, err)
	sent := agent.requests[1]
	require.True(t, sent.observe)
	require.Equal(t, int32(1), sent.predicate)
	require.Equal(t, "canary.test", sent.contains)
}

func TestReadPatchCountersAsksTheAgentAndReturnsWhatItHolds(t *testing.T) {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, int64(1_700_000_005_000))
	_ = binary.Write(&body, binary.BigEndian, uint32(1))
	for _, field := range []any{uint64(4), uint64(3), uint64(1), uint8(1), int64(1_700_000_001_000), int64(1_700_000_003_000), int64(1_700_000_000_000)} {
		_ = binary.Write(&body, binary.BigEndian, field)
	}
	agent := &fakePatchAgent{attachOK: true, counters: body.Bytes()}
	target := patchTarget(t, agent)

	counters, err := target.ReadPatchCounters(target.pid)

	require.NoError(t, err)
	require.Len(t, counters.Patches, 1)
	require.Equal(t, uint64(4), counters.Patches[0].Cookie)
	require.Equal(t, uint64(3), counters.Patches[0].Calls)
	require.Equal(t, uint64(1), counters.Patches[0].PredicateHits)
	require.Equal(t, agentctl.ReadPatchCounters, agent.operations()[len(agent.operations())-1])
	_, err = target.ReadPatchCounters(target.pid + 1)
	require.ErrorContains(t, err, "PID mismatch")
}

func TestAttachLivePatchOnAnOlderAgentFailsCleanly(t *testing.T) {
	agent := &fakePatchAgent{}
	target := patchTarget(t, agent)
	patch := &config.PatchSpec{Class: "a.B", Method: "lookup", Descriptor: "()Ljava/lang/String;", Action: config.PatchActionReturn, TTL: time.Minute}

	link, _, err := target.AttachLivePatch(target.pid, patch, time.Now().Add(time.Minute), 9)

	require.ErrorContains(t, err, "Unknown dynamic control operation")
	require.Nil(t, link)
}
