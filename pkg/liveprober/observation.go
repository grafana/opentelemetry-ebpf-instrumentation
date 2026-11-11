// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"errors"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
)

const (
	observationObserved = "observed"
	observationUnknown  = "unknown"
)

// Observation is what an observe-mode patch counted in the interval ObservedSince..ObservedUntil
// (both on the agent's clock). Say "reached / not reached under the observed traffic in this
// interval", never "affected"; a zero count with State "observed" means the method was not called
// in the interval, and State "unknown" means nothing is known (the numbers are then absent).
type Observation struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Calls is the number of calls of the exact method. PredicateHits is present only when the
	// patch has a predicate, and counts the calls whose argument matched it.
	Calls           *uint64    `json:"calls,omitempty"`
	PredicateHits   *uint64    `json:"predicate_hits,omitempty"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	ObservedSince   *time.Time `json:"observed_since,omitempty"`
	ObservedUntil   *time.Time `json:"observed_until,omitempty"`
	IntervalSeconds *float64   `json:"interval_seconds,omitempty"`
}

func unknownObservation(reason string) *Observation {
	return &Observation{State: observationUnknown, Reason: reason}
}

// observePatchesLocked fills in the counters of the observing patches in results, reading each
// process's agent at most once. Everything that cannot be read becomes "unknown".
func (m *Manager) observePatchesLocked(results []ProbeResult) {
	type reading struct {
		counters agentctl.Counters
		err      error
	}
	readings := map[int]reading{}
	for i := range results {
		result := &results[i]
		if !result.observing {
			continue
		}
		attachment := m.patches[patchKey{pid: result.PID, target: result.patchKey}]
		switch {
		case result.Status != patchStatusAttached:
			result.Observation = unknownObservation("patch is " + result.Status + ", so there are no counters")
			continue
		case attachment == nil:
			result.Observation = unknownObservation("patch is not attached")
			continue
		}
		read, done := readings[result.PID]
		if !done {
			read.counters, read.err = m.readCountersLocked(result.PID)
			readings[result.PID] = read
		}
		if read.err != nil {
			result.Observation = unknownObservation("counters could not be read: " + read.err.Error())
			continue
		}
		result.Observation = observationFor(read.counters, attachment.cookie)
	}
}

func (m *Manager) readCountersLocked(pid int) (agentctl.Counters, error) {
	bound, ok := m.targets[pid]
	if !ok {
		return agentctl.Counters{}, errors.New("target is not registered")
	}
	observer, ok := bound.tracer.(PatchObserver)
	if !ok {
		return agentctl.Counters{}, errors.New("target runtime cannot report counters")
	}
	return observer.ReadPatchCounters(app.PID(pid))
}

func observationFor(counters agentctl.Counters, cookie uint64) *Observation {
	for _, row := range counters.Patches {
		if row.Cookie != cookie {
			continue
		}
		observation := &Observation{State: observationObserved, Calls: &row.Calls}
		if row.HasPredicate {
			observation.PredicateHits = &row.PredicateHits
		}
		if !row.FirstSeen.IsZero() {
			observation.FirstSeen = &row.FirstSeen
		}
		if !row.LastSeen.IsZero() {
			observation.LastSeen = &row.LastSeen
		}
		since, until := row.Since, counters.Now
		observation.ObservedSince, observation.ObservedUntil = &since, &until
		interval := until.Sub(since).Seconds()
		observation.IntervalSeconds = &interval
		return observation
	}
	return unknownObservation("the agent has no counters for this patch (detached, expired or restarted)")
}
