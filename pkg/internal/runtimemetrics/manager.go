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
	log     *slog.Logger
	mu      sync.Mutex
}

func NewManager(log *slog.Logger) *Manager {
	return &Manager{
		readers: map[app.PID]*Reader{},
		log:     log,
	}
}

func (m *Manager) OnProcessEvent(pe *exec.ProcessEvent) {
	if pe == nil || pe.File == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch pe.Type {
	case exec.ProcessEventCreated:
		m.add(pe.File)
	case exec.ProcessEventTerminated:
		delete(m.readers, pe.File.Pid)
	}
}

func (m *Manager) add(file *exec.FileInfo) {
	delete(m.readers, file.Pid)

	if file.Service.SDKLanguage != svc.InstrumentableGolang {
		return
	}
	if !file.Service.Features.AppRuntime() {
		return
	}

	reader, err := NewReader(file)
	if err != nil {
		m.log.Debug("runtime metrics disabled for process", "pid", file.Pid, "error", err)
		return
	}
	m.readers[file.Pid] = reader
}

func (m *Manager) Snapshots() []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Snapshot, 0, len(m.readers))
	for pid, reader := range m.readers {
		snapshot, err := reader.ReadSnapshot()
		if err != nil {
			m.log.Debug("runtime metrics disabled after read failure", "pid", pid, "error", err)
			delete(m.readers, pid)
			continue
		}
		out = append(out, snapshot)
	}
	return out
}

func (m *Manager) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.readers) == 0
}
