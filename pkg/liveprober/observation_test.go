// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
)

const observeRuleJSON = `{"service":[{"target_pids":[123]}],"patches":[{"class":"app.Lookup","method":"lookup","descriptor":"(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;","mode":"observe","ttl":"30s","predicate":{"argument":1,"contains":"canary.test"}}]}`

// observingTracer is a patching tracer that can also report counters.
type observingTracer struct {
	patchingTracer
	counters agentctl.Counters
	err      error
	reads    int
}

func (o *observingTracer) ReadPatchCounters(app.PID) (agentctl.Counters, error) {
	o.reads++
	return o.counters, o.err
}

func applyObserve(t *testing.T, tracer TargetTracer) *Manager {
	t.Helper()
	m := patchManager(t, tracer)
	rule, err := RuleJSON([]byte(observeRuleJSON))
	require.NoError(t, err)
	results, err := m.ApplyRule("watch", rule)
	require.NoError(t, err)
	require.Equal(t, "attached", results[0].Status, results[0].Error)
	return m
}

func statusOf(t *testing.T, m *Manager) ProbeResult {
	t.Helper()
	results, ok := m.RuleStatus("watch")
	require.True(t, ok)
	require.Len(t, results, 1)
	return results[0]
}

func rowFor(cookie uint64) agentctl.PatchCounters {
	return agentctl.PatchCounters{Cookie: cookie, HasPredicate: true, Since: time.UnixMilli(1_700_000_000_000)}
}

func TestObservePatchReachesTheAgentAsObserveWithItsPredicate(t *testing.T) {
	tracer := &observingTracer{}
	applyObserve(t, tracer)

	require.Len(t, tracer.patches, 1)
	require.True(t, tracer.patches[0].spec.Observing())
	require.Equal(t, 1, tracer.patches[0].spec.Predicate.Argument)
	require.Equal(t, "canary.test", tracer.patches[0].spec.Predicate.Contains)
}

func TestNeverCalledIsAKnownZeroWithAnInterval(t *testing.T) {
	tracer := &observingTracer{}
	m := applyObserve(t, tracer)
	tracer.counters = agentctl.Counters{Now: time.UnixMilli(1_700_000_030_000), Patches: []agentctl.PatchCounters{rowFor(tracer.patches[0].cookie)}}

	observation := statusOf(t, m).Observation

	require.NotNil(t, observation)
	require.Equal(t, "observed", observation.State)
	require.NotNil(t, observation.Calls)
	require.Zero(t, *observation.Calls, "never called is a known zero")
	require.NotNil(t, observation.PredicateHits)
	require.Zero(t, *observation.PredicateHits)
	require.Nil(t, observation.FirstSeen)
	require.Nil(t, observation.LastSeen)
	require.InDelta(t, 30, *observation.IntervalSeconds, 0.001)
	body, err := json.Marshal(observation)
	require.NoError(t, err)
	require.Contains(t, string(body), `"calls":0`)
}

func TestBenignOnlyAndCanaryMixedAreToldApart(t *testing.T) {
	tracer := &observingTracer{}
	m := applyObserve(t, tracer)
	row := rowFor(tracer.patches[0].cookie)
	row.Calls, row.PredicateHits = 40, 0
	row.FirstSeen, row.LastSeen = time.UnixMilli(1_700_000_001_000), time.UnixMilli(1_700_000_020_000)
	tracer.counters = agentctl.Counters{Now: time.UnixMilli(1_700_000_030_000), Patches: []agentctl.PatchCounters{row}}
	benign := statusOf(t, m).Observation
	require.Equal(t, uint64(40), *benign.Calls)
	require.Zero(t, *benign.PredicateHits)

	row.Calls, row.PredicateHits = 41, 1
	tracer.counters.Patches = []agentctl.PatchCounters{row}
	mixed := statusOf(t, m).Observation
	require.Equal(t, uint64(41), *mixed.Calls)
	require.Equal(t, uint64(1), *mixed.PredicateHits)
	require.Equal(t, time.UnixMilli(1_700_000_001_000), *mixed.FirstSeen)
}

func TestCountersTheAgentNoLongerHasAreUnknownNotZero(t *testing.T) {
	tracer := &observingTracer{}
	m := applyObserve(t, tracer)
	tracer.counters = agentctl.Counters{Now: time.UnixMilli(1)} // agent answers, but has no entry

	observation := statusOf(t, m).Observation

	require.Equal(t, "unknown", observation.State)
	require.Contains(t, observation.Reason, "no counters")
	require.Nil(t, observation.Calls)
	require.Nil(t, observation.PredicateHits)
	body, err := json.Marshal(observation)
	require.NoError(t, err)
	require.NotContains(t, string(body), "calls")
}

func TestAnAgentThatCannotBeReadMakesTheCountersUnknown(t *testing.T) {
	tracer := &observingTracer{}
	m := applyObserve(t, tracer)
	tracer.err = errors.New("connection refused")

	observation := statusOf(t, m).Observation

	require.Equal(t, "unknown", observation.State)
	require.Contains(t, observation.Reason, "connection refused")
	require.Nil(t, observation.Calls)
}

func TestARuntimeWithoutCountersMakesThemUnknown(t *testing.T) {
	m := applyObserve(t, &patchingTracer{})

	observation := statusOf(t, m).Observation

	require.Equal(t, "unknown", observation.State)
	require.Contains(t, observation.Reason, "cannot report counters")
}

func TestAnExpiredObservePatchHasUnknownCounters(t *testing.T) {
	tracer := &observingTracer{}
	m := applyObserve(t, tracer)
	tracer.counters = agentctl.Counters{Now: time.UnixMilli(2), Patches: []agentctl.PatchCounters{rowFor(tracer.patches[0].cookie)}}
	setRuleExpiry(m, "watch", time.Now().Add(-time.Second))
	rule, err := RuleJSON([]byte(observeRuleJSON))
	require.NoError(t, err)
	_, err = m.ApplyRule("watch", rule)
	require.NoError(t, err)

	result := statusOf(t, m)

	require.Equal(t, "expired", result.Status)
	require.Equal(t, "unknown", result.Observation.State)
	require.Nil(t, result.Observation.Calls)
}

func TestEnforcingPatchesCarryNoObservationAndCostNoRead(t *testing.T) {
	tracer := &observingTracer{}
	m := patchManager(t, tracer)
	_, err := m.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)

	results, ok := m.RuleStatus("fix")

	require.True(t, ok)
	require.Nil(t, results[0].Observation)
	require.Zero(t, tracer.reads)
}

func TestTwoObservingPatchesOnOneProcessShareOneRead(t *testing.T) {
	tracer := &observingTracer{}
	m := patchManager(t, tracer)
	rule, err := RuleJSON([]byte(`{"service":[{"target_pids":[123]}],"patches":[` +
		`{"class":"a.B","method":"one","descriptor":"()Ljava/lang/String;","mode":"observe","ttl":"30s"},` +
		`{"class":"a.B","method":"two","descriptor":"()Ljava/lang/String;","mode":"observe","ttl":"30s"}]}`))
	require.NoError(t, err)
	_, err = m.ApplyRule("watch", rule)
	require.NoError(t, err)
	first, second := rowFor(tracer.patches[0].cookie), rowFor(tracer.patches[1].cookie)
	first.Calls, second.Calls = 3, 5
	tracer.counters = agentctl.Counters{Now: time.UnixMilli(2), Patches: []agentctl.PatchCounters{second, first}}

	results, _ := m.RuleStatus("watch")

	require.Equal(t, 1, tracer.reads)
	require.Equal(t, uint64(3), *results[0].Observation.Calls)
	require.Equal(t, uint64(5), *results[1].Observation.Calls)
}

func TestRuleStatusOfAnUnknownRule(t *testing.T) {
	m := patchManager(t, &observingTracer{})
	_, ok := m.RuleStatus("missing")
	require.False(t, ok)
}

func TestGetRuleStatusOverHTTP(t *testing.T) {
	tracer := &observingTracer{}
	m := applyObserve(t, tracer)
	row := rowFor(tracer.patches[0].cookie)
	row.Calls, row.PredicateHits = 2, 1
	tracer.counters = agentctl.Counters{Now: time.UnixMilli(1_700_000_010_000), Patches: []agentctl.PatchCounters{row}}
	handler := m.Handler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/rules/watch", nil))

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var body struct {
		ID     string `json:"id"`
		Probes []struct {
			Status      string `json:"status"`
			Observation struct {
				State         string  `json:"state"`
				Calls         *uint64 `json:"calls"`
				PredicateHits *uint64 `json:"predicate_hits"`
			} `json:"observation"`
		} `json:"probes"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Equal(t, "watch", body.ID)
	require.Equal(t, "attached", body.Probes[0].Status)
	require.Equal(t, "observed", body.Probes[0].Observation.State)
	require.Equal(t, uint64(2), *body.Probes[0].Observation.Calls)
	require.Equal(t, uint64(1), *body.Probes[0].Observation.PredicateHits)

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/rules/nope", nil))
	require.Equal(t, http.StatusNotFound, missing.Code)
}
