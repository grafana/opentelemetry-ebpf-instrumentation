// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

type invocationReporter struct {
	imetrics.NoopReporter
	counters imetrics.DynamicProbeCounters
	active   map[uint64]bool
}

func (r *invocationReporter) DynamicProbeInvocations(id uint64, probe *imetrics.DynamicProbeCounter) {
	r.counters.DynamicProbeInvocations(id, probe)
	if r.active == nil {
		r.active = map[uint64]bool{}
	}
	if probe == nil {
		delete(r.active, id)
	} else {
		r.active[id] = true
	}
}

func TestInvocationMetricsRuleLifecycle(t *testing.T) {
	m, tracer := dynamicManager(t)
	reporter := &invocationReporter{}
	m.Configure(config.DefaultDynamicInstrumentationConfig(), nil, reporter)
	service := svc.Attrs{UID: svc.UID{Name: "checkout"}}
	require.NoError(t, m.RegisterTarget(123, 1, tracer, func() svc.Attrs { return service }))
	rule := ruleFor(t, "main.*")
	_, err := m.ApplyRule("test", rule)
	require.NoError(t, err)
	require.Len(t, reporter.counters.CollectDynamicProbes(false), 2)
	require.NoError(t, m.SetConfigRules([]config.DynamicInstrumentationRule{rule}))
	require.NoError(t, m.DeleteRule("test"))
	require.Len(t, reporter.counters.CollectDynamicProbes(false), 2, "shared owners reuse counters")
	tracer.links[0].count = 7
	var total uint64
	for _, sample := range reporter.counters.CollectDynamicProbes(false) {
		total += sample.Count
	}
	require.Equal(t, uint64(7), total)
	service.UID.Name = "sdk-checkout"
	for _, sample := range reporter.counters.CollectDynamicProbes(false) {
		value, _ := sample.Attributes.Value("service.name")
		require.Equal(t, "sdk-checkout", value.AsString(), "resolve metadata at collection time")
	}
	require.NoError(t, m.DeleteFunctions(rule.Service, "main.one"))
	require.Len(t, reporter.counters.CollectDynamicProbes(false), 1)
	require.NoError(t, m.SetConfigRules(nil))
	require.Empty(t, reporter.counters.CollectDynamicProbes(false))
	require.Empty(t, reporter.active)
	_, err = m.ApplyRule("test", rule)
	require.NoError(t, err)
	for _, sample := range reporter.counters.CollectDynamicProbes(false) {
		require.Zero(t, sample.Count)
	}
	// Replacement must drop the previous attachment's labels and counter.
	rule.Spans[0].Name = "replacement"
	_, err = m.ApplyRule("test", rule)
	require.NoError(t, err)
	require.Len(t, reporter.counters.CollectDynamicProbes(false), 2)
	m.UnregisterTarget(123)
	require.Empty(t, reporter.counters.CollectDynamicProbes(false))
	require.Empty(t, reporter.active)
}

func TestInvocationMetricsCleanup(t *testing.T) {
	for _, action := range []string{"delete", "expire", "replace", "exit", "pid_reuse", "close"} {
		t.Run(action, func(t *testing.T) {
			tracer := &fakeTracer{}
			m := testManager(t, tracer)
			t.Cleanup(func() { require.NoError(t, m.Close()) })
			reporter := &invocationReporter{}
			m.Configure(config.DefaultDynamicInstrumentationConfig(), nil, reporter)
			_, err := m.Apply("test", spec(1, 0x100))
			require.NoError(t, err)
			tracer.links[0].count = 7
			original := reporter.counters.CollectDynamicProbes(false)
			require.Len(t, original, 1)
			require.Equal(t, uint64(7), original[0].Count)
			switch action {
			case "delete":
				require.NoError(t, m.Delete("test"))
			case "expire":
				m.expire("test", 1)
			case "replace":
				_, err = m.Apply("test", spec(2, 0x100))
				require.NoError(t, err)
				replacement := reporter.counters.CollectDynamicProbes(false)
				require.Len(t, replacement, 1)
				require.Zero(t, replacement[0].Count)
				require.NotEqual(t, original[0].Attributes, replacement[0].Attributes)
				require.NoError(t, m.Delete("test"))
			case "exit":
				m.UnregisterTarget(123)
			case "pid_reuse":
				m.identity = func(int) (processIdentity, error) { return processIdentity{startTime: 99}, nil }
				require.NoError(t, m.RegisterTarget(123, 1, tracer, nil))
			case "close":
				require.NoError(t, m.Close())
			}
			require.Empty(t, reporter.counters.CollectDynamicProbes(false))
			require.Empty(t, reporter.active)
		})
	}
}

func TestInvocationMetricsFailedAttach(t *testing.T) {
	m, tracer := dynamicManager(t)
	reporter := &invocationReporter{}
	m.Configure(config.DefaultDynamicInstrumentationConfig(), nil, reporter)
	tracer.rejectAt = 1
	_, err := m.ApplyRule("test", ruleFor(t, "main.one"))
	require.NoError(t, err)
	require.Empty(t, reporter.counters.CollectDynamicProbes(false))
	require.Empty(t, reporter.active)
	_, err = m.Apply("offset", spec(1, 0x100))
	require.Error(t, err)
	require.Empty(t, reporter.counters.CollectDynamicProbes(false))
	require.Empty(t, reporter.active)
}
