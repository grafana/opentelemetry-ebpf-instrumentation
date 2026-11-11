// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

const patchRuleJSON = `{"service":[{"target_pids":[123]}],"patches":[{"class":"org.apache.logging.log4j.core.lookup.JndiLookup","method":"lookup","descriptor":"(Lorg/apache/logging/log4j/core/LogEvent;Ljava/lang/String;)Ljava/lang/String;","action":"return","value":"%s","ttl":"30s"}]}`

type attachedPatch struct {
	spec      config.PatchSpec
	expiresAt time.Time
	cookie    uint64
	link      *fakeLink
}

type patchingTracer struct {
	resolvingTracer
	patches []*attachedPatch
	err     error
}

func (p *patchingTracer) AttachLivePatch(_ app.PID, patch *config.PatchSpec, expiresAt time.Time, cookie uint64) (io.Closer, error) {
	if p.err != nil {
		return nil, p.err
	}
	attached := &attachedPatch{spec: *patch, expiresAt: expiresAt, cookie: cookie, link: &fakeLink{}}
	p.patches = append(p.patches, attached)
	return attached.link, nil
}

func patchRule(t *testing.T, value string) config.DynamicInstrumentationRule {
	t.Helper()
	rule, err := RuleJSON([]byte(fmt.Sprintf(patchRuleJSON, value)))
	require.NoError(t, err)
	return rule
}

func patchManager(t *testing.T, tracer TargetTracer) *Manager {
	t.Helper()
	m, _ := dynamicManager(t)
	require.NoError(t, m.RegisterTarget(123, 1, tracer, nil))
	return m
}

func TestPatchRuleAttachesOnceAndDeleteRemovesIt(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)

	before := time.Now()
	results, err := m.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "attached", results[0].Status)
	require.Len(t, tracer.patches, 1)
	require.Equal(t, "none", tracer.patches[0].spec.Value)
	require.WithinDuration(t, before.Add(30*time.Second), tracer.patches[0].expiresAt, 5*time.Second)

	_, err = m.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)
	require.Len(t, tracer.patches, 1, "reapplying an identical rule must not extend the TTL")

	require.NoError(t, m.DeleteRule("fix"))
	require.True(t, tracer.patches[0].link.closed, "DELETE must detach the patch")
}

func TestPatchRuleChangeAttachesNewBeforeClosingOld(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)

	_, err := m.ApplyRule("fix", patchRule(t, "one"))
	require.NoError(t, err)
	_, err = m.ApplyRule("fix", patchRule(t, "two"))
	require.NoError(t, err)

	require.Len(t, tracer.patches, 2)
	require.True(t, tracer.patches[0].link.closed)
	require.False(t, tracer.patches[1].link.closed)
	require.Greater(t, tracer.patches[1].cookie, tracer.patches[0].cookie)
}

func setRuleExpiry(m *Manager, id string, expiresAt time.Time) {
	rule := m.rules["api/"+id]
	for target := range rule.patchExpiry {
		rule.patchExpiry[target] = expiresAt
	}
}

func restartJVM(t *testing.T, m *Manager, tracer TargetTracer, startTime uint64) {
	t.Helper()
	m.identity = func(int) (processIdentity, error) { return processIdentity{startTime: startTime}, nil }
	require.NoError(t, m.RegisterTarget(123, 1, tracer, nil))
}

func TestExpiredPatchIsReportedAndNotReapplied(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)
	_, err := m.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)
	setRuleExpiry(m, "fix", time.Now().Add(-time.Second))

	results, err := m.ApplyRule("fix", patchRule(t, "none"))

	require.NoError(t, err)
	require.Equal(t, "expired", results[0].Status)
	require.Len(t, tracer.patches, 1, "an expired patch must not come back")
}

func TestJVMRestartReattachesWithOriginalExpiryUntilItPasses(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)
	_, err := m.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)
	halfway := time.Now().Add(15 * time.Second)
	setRuleExpiry(m, "fix", halfway)

	restartJVM(t, m, tracer, 43)

	require.Len(t, tracer.patches, 2, "a restarted JVM must get the patch again")
	require.Equal(t, halfway, tracer.patches[1].expiresAt, "re-attach must reuse the rule's expiry, not restart the TTL")

	setRuleExpiry(m, "fix", time.Now().Add(-time.Second))
	restartJVM(t, m, tracer, 44)

	require.Len(t, tracer.patches, 2, "no re-attach once the expiry has passed")
	results, _ := m.RuleResults("fix")
	require.Equal(t, "expired", results[0].Status)
}

func TestPatchRuleReportsUnsupportedTargetAndAgentError(t *testing.T) {
	m := patchManager(t, &resolvingTracer{})
	results, err := m.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)
	require.Equal(t, "error", results[0].Status)
	require.Contains(t, results[0].Error, "does not support patches")

	failing := patchManager(t, &patchingTracer{err: errors.New("Unknown dynamic control operation")})
	results, err = failing.ApplyRule("fix", patchRule(t, "none"))
	require.NoError(t, err)
	require.Equal(t, "error", results[0].Status)
	require.Contains(t, results[0].Error, "Unknown dynamic control operation")
}

func TestPatchRulesRejectInvalidSpecs(t *testing.T) {
	m := patchManager(t, &patchingTracer{})
	valid := fmt.Sprintf(patchRuleJSON, "none")
	for name, change := range map[string][2]string{
		"zero ttl":          {`"ttl":"30s"`, `"ttl":"0s"`},
		"unknown action":    {`"action":"return"`, `"action":"throw"`},
		"non-string return": {`)Ljava/lang/String;","action"`, `)I","action"`},
	} {
		rule, err := RuleJSON([]byte(strings.Replace(valid, change[0], change[1], 1)))
		require.NoError(t, err, name)

		_, err = m.ApplyRule("bad", rule)

		require.Error(t, err, name)
	}
}
