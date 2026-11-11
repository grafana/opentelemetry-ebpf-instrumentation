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
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
)

const patchRuleJSON = `{"service":[{"target_pids":[123]}],"patches":[{"class":"org.apache.logging.log4j.core.lookup.JndiLookup","method":"lookup","descriptor":"(Lorg/apache/logging/log4j/core/LogEvent;Ljava/lang/String;)Ljava/lang/String;","action":"return","value":"%s","ttl":"30s"}]}`

type attachedPatch struct {
	spec      config.PatchSpec
	expiresAt time.Time
	cookie    uint64
	link      *fakeLink
}

var testEvidence = agentctl.PatchEvidence{Loader: "loader:1", ArtifactSHA256: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64)}

type patchingTracer struct {
	resolvingTracer
	patches []*attachedPatch
	err     error
}

func (p *patchingTracer) AttachLivePatch(_ app.PID, patch *config.PatchSpec, expiresAt time.Time, cookie uint64) (io.Closer, agentctl.PatchEvidence, error) {
	if p.err != nil {
		return nil, agentctl.PatchEvidence{}, p.err
	}
	attached := &attachedPatch{spec: *patch, expiresAt: expiresAt, cookie: cookie, link: &fakeLink{}}
	p.patches = append(p.patches, attached)
	return attached.link, testEvidence, nil
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

const identityRuleJSON = `{"service":[{"target_pids":[123]}],"patches":[{"class":"a.B","method":"lookup","descriptor":"(Ljava/lang/String;)Ljava/lang/String;","action":"return","value":"none","ttl":"30s","loader":"loader:1","artifact_sha256":"%s","fingerprint":"%s","require_identity":true}]}`

func TestPatchStatusReportsTheV0EvidenceTheAgentResolved(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)
	rule, err := RuleJSON([]byte(fmt.Sprintf(identityRuleJSON, strings.Repeat("a", 64), strings.Repeat("b", 64))))
	require.NoError(t, err)

	results, err := m.ApplyRule("fix", rule)

	require.NoError(t, err)
	require.Equal(t, "attached", results[0].Status)
	require.NotNil(t, results[0].Identity)
	require.Equal(t, testEvidence, *results[0].Identity)
	sent := tracer.patches[0].spec
	require.True(t, sent.RequireIdentity)
	require.Equal(t, "loader:1", sent.Loader)
	require.Equal(t, strings.Repeat("a", 64), sent.ArtifactSHA256)
	require.Equal(t, strings.Repeat("b", 64), sent.Fingerprint)

	results, err = m.ApplyRule("fix", rule)
	require.NoError(t, err)
	require.Len(t, tracer.patches, 1, "an identical rule must not attach again")
	require.NotNil(t, results[0].Identity, "the evidence must survive a re-apply")
	require.Equal(t, testEvidence, *results[0].Identity)
}

func TestPatchRefusalIsReportedWithItsReason(t *testing.T) {
	tracer := &patchingTracer{err: errors.New("PatchRefusal AMBIGUOUS_LOADER: 2 loaders define a.B.lookup; choose one with loader: loader:1 (...), loader:2 (...)")}
	m := patchManager(t, tracer)

	results, err := m.ApplyRule("fix", patchRule(t, "none"))

	require.NoError(t, err)
	require.Equal(t, "error", results[0].Status)
	require.Equal(t, "AMBIGUOUS_LOADER", results[0].Reason)
	require.Contains(t, results[0].Error, "loader:2")
	require.Nil(t, results[0].Identity)
}

func TestARefusalWithoutACodeHasNoReason(t *testing.T) {
	tracer := &patchingTracer{err: errors.New("connection refused")}
	m := patchManager(t, tracer)

	results, err := m.ApplyRule("fix", patchRule(t, "none"))

	require.NoError(t, err)
	require.Empty(t, results[0].Reason)
}

const loaderPatchRuleJSON = `{"service":[{"target_pids":[123]}],"patches":[{"class":"app.Sample","method":"lookup","descriptor":"(Ljava/lang/String;)Ljava/lang/String;","action":"return","value":"%s","ttl":"30s","loader":"%s"}]}`

func loaderPatchRule(t *testing.T, value, loader string) config.DynamicInstrumentationRule {
	t.Helper()
	rule, err := RuleJSON([]byte(fmt.Sprintf(loaderPatchRuleJSON, value, loader)))
	require.NoError(t, err)
	return rule
}

func TestDeletingTheLivePatchRuleDetachesEvenWhileAnExpiredRuleTargetsTheSameMethod(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)
	_, err := m.ApplyRule("live", patchRule(t, "two"))
	require.NoError(t, err)
	old := patchRule(t, "one")
	m.rules["api/old"] = ruleState{definition: old, patchExpiry: patchExpiries(ruleState{}, old)}
	setRuleExpiry(m, "old", time.Now().Add(-time.Second))

	require.NoError(t, m.DeleteRule("live"))

	require.True(t, tracer.patches[0].link.closed, "the deleted rule's patch must be detached; an expired rule asks for nothing")
}

func TestAnExpiredRuleDoesNotBlockALiveRuleForTheSameMethod(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)
	old := patchRule(t, "one")
	m.rules["api/old"] = ruleState{definition: old, patchExpiry: patchExpiries(ruleState{}, old)}
	setRuleExpiry(m, "old", time.Now().Add(-time.Second))

	for range 20 { // reconcile order over the rules map is random
		results, err := m.ApplyRule("live", patchRule(t, "two"))
		require.NoError(t, err)
		require.Equal(t, "attached", results[0].Status, results[0].Error)
	}
}

func TestPatchesForTheSameMethodInDifferentLoadersDoNotCollide(t *testing.T) {
	tracer := &patchingTracer{}
	m := patchManager(t, tracer)

	for range 20 {
		resB, err := m.ApplyRule("b", loaderPatchRule(t, "patched-B", "loader:2"))
		require.NoError(t, err)
		require.Equal(t, "attached", resB[0].Status, resB[0].Error)
		resC, err := m.ApplyRule("c", loaderPatchRule(t, "patched-C", "loader:3"))
		require.NoError(t, err)
		require.Equal(t, "attached", resC[0].Status, resC[0].Error)
	}
	require.Len(t, tracer.patches, 2, "each loader's patch attaches once")

	require.NoError(t, m.DeleteRule("b"))
	require.True(t, tracer.patches[0].link.closed, "deleting loader 2's rule detaches loader 2's patch")
	require.False(t, tracer.patches[1].link.closed, "and leaves loader 3's patch attached")
}
