// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agentctl // import "go.opentelemetry.io/obi/pkg/internal/agentctl"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

const (
	List byte = iota + 1
	Attach
	Detach
	Claim
	AttachPatch
	// ReadPatchCounters returns the counters of the observing patches that are still installed.
	ReadPatchCounters
)

// Patch is the payload of the AttachPatch operation.
type Patch struct {
	Class      string
	Method     string
	Descriptor string
	Value      string
	ExpiresAt  time.Time
	// Identity assertions the agent verifies before patching. Empty fields are not asserted.
	// With RequireIdentity the agent refuses a patch that does not assert all three.
	RequireIdentity bool
	Loader          string
	ArtifactSHA256  string
	Fingerprint     string
	// Observe makes the patch count calls instead of returning Value; Predicate, if set, also
	// counts the calls whose String argument contains the literal.
	Observe   bool
	Predicate *Predicate
}

// Predicate is the closed observe-mode predicate: parameter Argument contains Contains.
type Predicate struct {
	Argument int
	Contains string
}

// PatchCounters is what one observing patch has counted. A zero FirstSeen/LastSeen means the
// method was not called in the interval; it never means the counters are unknown (an unknown
// counter has no entry at all).
type PatchCounters struct {
	Cookie        uint64
	Calls         uint64
	PredicateHits uint64
	HasPredicate  bool
	FirstSeen     time.Time
	LastSeen      time.Time
	// Since is when the agent started observing, on the agent's clock.
	Since time.Time
}

// Counters is the reply of ReadPatchCounters. Now is the agent's clock at the time of the read,
// so the interval Since..Now is exact even if the two clocks differ.
type Counters struct {
	Now     time.Time
	Patches []PatchCounters
}

// PatchEvidence is the V0 evidence the agent resolved for the one method it patched: which class
// loader, which artifact (SHA-256 of the jar) and which method fingerprint. An empty field means
// the agent could not establish it (and the patch did not assert it).
type PatchEvidence struct {
	Loader         string `json:"loader"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
}

const patchActionReturn byte = 1

// Exchange implements the private agent protocol used by Java and Node.js.
func Exchange(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, operation byte, method string, cookie uint64) ([]string, error) {
	var request bytes.Buffer
	if operation == Attach {
		writeString(&request, method)
	}
	if operation == Attach || operation == Detach {
		_ = binary.Write(&request, binary.BigEndian, cookie)
	}
	connection, err := send(ctx, pid, port, token, session, operation, request.Bytes())
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := readStatus(connection); err != nil {
		return nil, err
	}
	if operation != List {
		return nil, nil
	}
	return readSymbols(connection)
}

// ExchangePatch sends the AttachPatch operation, which Java agents from before it existed reject.
// A refused or mismatched target is an error whose text starts with "PatchRefusal <REASON>:".
func ExchangePatch(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, patch Patch, cookie uint64) (PatchEvidence, error) {
	var request bytes.Buffer
	writeString(&request, patch.Class)
	writeString(&request, patch.Method)
	writeString(&request, patch.Descriptor)
	request.WriteByte(patchActionReturn)
	writeString(&request, patch.Value)
	_ = binary.Write(&request, binary.BigEndian, patch.ExpiresAt.UnixMilli())
	_ = binary.Write(&request, binary.BigEndian, cookie)
	request.WriteByte(boolByte(patch.RequireIdentity))
	writeString(&request, patch.Loader)
	writeString(&request, patch.ArtifactSHA256)
	writeString(&request, patch.Fingerprint)
	request.WriteByte(boolByte(patch.Observe))
	predicateArgument, predicateContains := int32(-1), ""
	if patch.Predicate != nil {
		predicateArgument, predicateContains = int32(patch.Predicate.Argument), patch.Predicate.Contains
	}
	_ = binary.Write(&request, binary.BigEndian, predicateArgument)
	writeString(&request, predicateContains)
	connection, err := send(ctx, pid, port, token, session, AttachPatch, request.Bytes())
	if err != nil {
		return PatchEvidence{}, err
	}
	defer connection.Close()
	if err := readStatus(connection); err != nil {
		return PatchEvidence{}, err
	}
	var evidence PatchEvidence
	for _, field := range []*string{&evidence.Loader, &evidence.ArtifactSHA256, &evidence.Fingerprint} {
		if *field, err = ReadString(connection); err != nil {
			return PatchEvidence{}, fmt.Errorf("reading patch evidence: %w", err)
		}
	}
	return evidence, nil
}

// ExchangeCounters reads the counters of every observing patch the agent still has.
func ExchangeCounters(ctx context.Context, pid app.PID, port uint32, token, session [16]byte) (Counters, error) {
	connection, err := send(ctx, pid, port, token, session, ReadPatchCounters, nil)
	if err != nil {
		return Counters{}, err
	}
	defer connection.Close()
	if err := readStatus(connection); err != nil {
		return Counters{}, err
	}
	var now int64
	var count uint32
	if err := binary.Read(connection, binary.BigEndian, &now); err != nil {
		return Counters{}, fmt.Errorf("reading counters: %w", err)
	}
	if err := binary.Read(connection, binary.BigEndian, &count); err != nil {
		return Counters{}, fmt.Errorf("reading counters: %w", err)
	}
	if count > 100000 {
		return Counters{}, fmt.Errorf("agent counter list exceeds limit: %d", count)
	}
	result := Counters{Now: time.UnixMilli(now), Patches: make([]PatchCounters, 0, count)}
	for range count {
		var row struct {
			Cookie, Calls, Hits uint64
			HasPredicate        uint8
			First, Last, Since  int64
		}
		if err := binary.Read(connection, binary.BigEndian, &row); err != nil {
			return Counters{}, fmt.Errorf("reading counters: %w", err)
		}
		entry := PatchCounters{
			Cookie: row.Cookie, Calls: row.Calls, PredicateHits: row.Hits,
			HasPredicate: row.HasPredicate != 0, Since: time.UnixMilli(row.Since),
		}
		if row.First != 0 {
			entry.FirstSeen = time.UnixMilli(row.First)
		}
		if row.Last != 0 {
			entry.LastSeen = time.UnixMilli(row.Last)
		}
		result.Patches = append(result.Patches, entry)
	}
	return result, nil
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

// send connects inside the target's network namespace and writes one request. The returned
// connection is closed early if ctx ends, and must be closed by the caller.
func send(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, operation byte, payload []byte) (net.Conn, error) {
	if port == 0 || port > 65535 {
		return nil, errors.New("dynamic agent is not ready")
	}
	var connection net.Conn
	err := netns.WithNetNS(int(pid), func() error {
		var err error
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		return err
	})
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		connection.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	var request bytes.Buffer
	request.Write(token[:])
	request.Write(session[:])
	request.WriteByte(operation)
	request.Write(payload)
	if _, err := io.Copy(connection, &request); err != nil {
		stop()
		connection.Close()
		return nil, err
	}
	return &stoppingConn{Conn: connection, stop: stop}, nil
}

type stoppingConn struct {
	net.Conn
	stop func() bool
}

func (c *stoppingConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func readStatus(connection io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(connection, status[:]); err != nil {
		return err
	}
	if status[0] == 0 {
		return nil
	}
	message, err := ReadString(connection)
	if err != nil {
		return err
	}
	return errors.New(message)
}

func readSymbols(connection io.Reader) ([]string, error) {
	var count uint32
	if err := binary.Read(connection, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > 100000 {
		return nil, fmt.Errorf("agent symbol list exceeds limit: %d", count)
	}
	symbols := make([]string, 0, count)
	size := 0
	for range count {
		symbol, err := ReadString(connection)
		if err != nil {
			return nil, err
		}
		size += len(symbol)
		if size > 64<<20 {
			return nil, errors.New("agent symbol catalog exceeds byte limit")
		}
		symbols = append(symbols, symbol)
	}
	slices.Sort(symbols)
	return symbols, nil
}

func writeString(buffer *bytes.Buffer, value string) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	buffer.WriteString(value)
}

func ReadString(reader io.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return "", err
	}
	if size > 65536 {
		return "", errors.New("agent control string exceeds limit")
	}
	text := make([]byte, size)
	_, err := io.ReadFull(reader, text)
	return string(text), err
}
