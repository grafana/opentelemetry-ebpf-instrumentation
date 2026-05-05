// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type Manager struct {
	readers map[app.PID]*Reader
	failed  map[app.PID]struct{}
	log     *slog.Logger
	mu      sync.Mutex
}

func NewManager(log *slog.Logger) *Manager {
	return &Manager{
		readers: map[app.PID]*Reader{},
		failed:  map[app.PID]struct{}{},
		log:     log,
	}
}

func (m *Manager) OnProcessEvent(pe *exec.ProcessEvent) {
	if pe == nil || pe.File == nil {
		return
	}

	switch pe.Type {
	case exec.ProcessEventCreated:
		m.add(pe.File)
	case exec.ProcessEventTerminated:
		m.remove(pe.File.Pid)
	}
}

func (m *Manager) add(file *exec.FileInfo) {
	if file.Service.SDKLanguage != svc.InstrumentableGolang {
		return
	}
	if !file.Service.Features.AppRuntime() {
		return
	}

	reader, err := NewReader(file)
	if err != nil {
		m.mu.Lock()
		_, alreadyFailed := m.failed[file.Pid]
		m.failed[file.Pid] = struct{}{}
		m.mu.Unlock()
		if !alreadyFailed {
			m.log.Warn("runtime metrics disabled for process", "pid", file.Pid, "error", err)
		} else {
			m.log.Debug("runtime metrics still failing for process", "pid", file.Pid, "error", err)
		}
		return
	}

	m.mu.Lock()
	if existing, ok := m.readers[file.Pid]; ok {
		_ = existing.Close()
	}
	m.readers[file.Pid] = reader
	delete(m.failed, file.Pid)
	m.mu.Unlock()
}

func (m *Manager) remove(pid app.PID) {
	m.mu.Lock()
	reader, ok := m.readers[pid]
	delete(m.readers, pid)
	delete(m.failed, pid)
	m.mu.Unlock()
	if ok {
		_ = reader.Close()
	}
}

func (m *Manager) Snapshots() []Snapshot {
	m.mu.Lock()
	pending := make([]*Reader, 0, len(m.readers))
	pids := make([]app.PID, 0, len(m.readers))
	for pid, reader := range m.readers {
		pending = append(pending, reader)
		pids = append(pids, pid)
	}
	m.mu.Unlock()

	out := make([]Snapshot, 0, len(pending))
	var retired []app.PID
	for i, reader := range pending {
		snapshot, err := reader.ReadSnapshot()
		if err != nil {
			if reader.failing() {
				m.log.Warn("retiring runtime metrics reader after repeated failures", "pid", pids[i], "error", err)
				retired = append(retired, pids[i])
			} else {
				m.log.Debug("runtime metrics read failed", "pid", pids[i], "error", err)
			}
			continue
		}
		out = append(out, snapshot)
	}

	for _, pid := range retired {
		m.remove(pid)
	}
	return out
}

func (m *Manager) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.readers) == 0
}
