// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober

import (
	"errors"
	"io"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

type fakeLink struct {
	closed bool
	count  uint64
}

func (l *fakeLink) Invocations() (uint64, error) {
	if l.closed {
		return 0, errors.New("closed")
	}
	return l.count, nil
}

func (l *fakeLink) Close() error { l.closed = true; return nil }

type fakeTracer struct {
	links    []*fakeLink
	rejectAt int
}

func (f *fakeTracer) AttachLiveSpan(_ app.PID, _ uint32, _ *config.CustomSpanSpec, _ uint64, _ string, _ uint64) (io.Closer, error) {
	if f.rejectAt > 0 && len(f.links)+1 >= f.rejectAt {
		return nil, errors.New("spec IDs exhausted")
	}
	link := &fakeLink{}
	f.links = append(f.links, link)
	return link, nil
}

func testManager(t *testing.T, tracer *fakeTracer) *Manager {
	t.Helper()
	m := New()
	m.identity = func(int) (processIdentity, error) { return processIdentity{startTime: 42}, nil }
	if err := m.RegisterTarget(123, 1, tracer, nil); err != nil {
		t.Fatal(err)
	}
	return m
}

func spec(generation, offset uint64) ProbeSpec {
	return ProbeSpec{Generation: generation, PID: 123, Offset: Offset(offset), SpanName: "marker"}
}

func TestUpdateOneProbeKeepsOtherLink(t *testing.T) {
	tracer := &fakeTracer{}
	m := testManager(t, tracer)
	defer m.Close()
	if _, err := m.Apply("A", spec(1, 0x100)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply("B", spec(1, 0x200)); err != nil {
		t.Fatal(err)
	}
	bLink := tracer.links[1]
	bID := m.Snapshot()["B"].LinkID
	if _, err := m.Apply("A", spec(2, 0x300)); err != nil {
		t.Fatal(err)
	}
	if !tracer.links[0].closed {
		t.Fatal("A v1 link was not closed")
	}
	if bLink.closed || m.Snapshot()["B"].LinkID != bID {
		t.Fatal("B link changed during A update")
	}
	if err := m.Delete("A"); err != nil {
		t.Fatal(err)
	}
	if !tracer.links[2].closed || bLink.closed {
		t.Fatal("A delete changed B")
	}
}

func TestFailedUpdateRetainsBothLinks(t *testing.T) {
	tracer := &fakeTracer{rejectAt: 3}
	m := testManager(t, tracer)
	defer m.Close()
	if _, err := m.Apply("A", spec(1, 0x100)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply("B", spec(1, 0x200)); err != nil {
		t.Fatal(err)
	}
	before := m.Snapshot()
	if _, err := m.Apply("A", spec(2, 0x300)); err == nil {
		t.Fatal("expected exhausted map failure")
	}
	after := m.Snapshot()
	if after["A"].LinkID != before["A"].LinkID || after["B"].LinkID != before["B"].LinkID {
		t.Fatal("failed update changed link identities")
	}
	if tracer.links[0].closed || tracer.links[1].closed {
		t.Fatal("failed update detached live probe")
	}
}

func TestRejectSameGenerationDriftAndMissingPID(t *testing.T) {
	tracer := &fakeTracer{}
	m := testManager(t, tracer)
	defer m.Close()
	if _, err := m.Apply("A", spec(1, 0x100)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply("A", spec(1, 0x200)); !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	bad := spec(2, 0x200)
	bad.PID = 999
	if _, err := m.Apply("A", bad); !errors.Is(err, ErrNotReady) {
		t.Fatalf("want not ready, got %v", err)
	}
	if tracer.links[0].closed {
		t.Fatal("invalid update detached A")
	}
}

func TestOldExpiryCannotCloseNewGeneration(t *testing.T) {
	tracer := &fakeTracer{}
	m := testManager(t, tracer)
	defer m.Close()
	if _, err := m.Apply("A", spec(1, 0x100)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply("A", spec(2, 0x200)); err != nil {
		t.Fatal(err)
	}
	m.expire("A", 1)
	if tracer.links[1].closed || m.Snapshot()["A"].Status != "attached" {
		t.Fatal("old generation expiry closed new link")
	}
}
