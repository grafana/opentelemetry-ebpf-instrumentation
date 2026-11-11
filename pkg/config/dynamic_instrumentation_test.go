// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func validPatch() PatchSpec {
	return PatchSpec{
		Class:      "org.apache.logging.log4j.core.lookup.JndiLookup",
		Method:     "lookup",
		Descriptor: "(Lorg/apache/logging/log4j/core/LogEvent;Ljava/lang/String;)Ljava/lang/String;",
		Action:     PatchActionReturn,
		Value:      "none",
		TTL:        time.Minute,
	}
}

func TestPatchSpecValidate(t *testing.T) {
	valid := validPatch()
	require.NoError(t, valid.Validate())

	for name, mutate := range map[string]func(*PatchSpec){
		"missing class":      func(p *PatchSpec) { p.Class = "" },
		"missing descriptor": func(p *PatchSpec) { p.Descriptor = "" },
		"not a descriptor":   func(p *PatchSpec) { p.Descriptor = "lookup" },
		"non-String return":  func(p *PatchSpec) { p.Descriptor = "(Ljava/lang/String;)I" },
		"unknown action":     func(p *PatchSpec) { p.Action = "throw" },
		"no ttl":             func(p *PatchSpec) { p.TTL = 0 },
		"ttl too long":       func(p *PatchSpec) { p.TTL = MaxPatchTTL + time.Second },
	} {
		patch := validPatch()
		mutate(&patch)
		require.Error(t, patch.Validate(), name)
	}
}

func TestPatchSpecValidatesItsIdentityAssertions(t *testing.T) {
	hash := "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef"
	valid := validPatch()
	valid.Loader, valid.ArtifactSHA256, valid.Fingerprint = "loader:12", hash, hash
	require.NoError(t, valid.Validate())
	valid.RequireIdentity = true
	require.NoError(t, valid.Validate())
	valid.Loader = "loader:bootstrap"
	require.NoError(t, valid.Validate())

	for name, mutate := range map[string]func(*PatchSpec){
		"loader not a selector":      func(p *PatchSpec) { p.Loader = "app" },
		"loader with spaces":         func(p *PatchSpec) { p.Loader = "loader:1 " },
		"artifact too short":         func(p *PatchSpec) { p.ArtifactSHA256 = "abc" },
		"artifact not hex":           func(p *PatchSpec) { p.ArtifactSHA256 = hash[:63] + "g" },
		"fingerprint too long":       func(p *PatchSpec) { p.Fingerprint = hash + "0" },
		"strict without loader":      func(p *PatchSpec) { p.RequireIdentity, p.Loader = true, "" },
		"strict without artifact":    func(p *PatchSpec) { p.RequireIdentity, p.ArtifactSHA256 = true, "" },
		"strict without fingerprint": func(p *PatchSpec) { p.RequireIdentity, p.Fingerprint = true, "" },
	} {
		patch := validPatch()
		patch.Loader, patch.ArtifactSHA256, patch.Fingerprint = "loader:1", hash, hash
		mutate(&patch)
		require.Error(t, patch.Validate(), name)
	}
}

func TestPatchSpecValidatesObserveMode(t *testing.T) {
	observe := validPatch()
	observe.Mode, observe.Action, observe.Value = PatchModeObserve, "", ""
	require.NoError(t, observe.Validate())
	require.True(t, observe.Observing())

	observe.Predicate = &PatchPredicate{Argument: 1, Contains: "canary.example"}
	require.NoError(t, observe.Validate())

	// Counting works for any return type; enforcing still needs a String.
	observe.Descriptor = "(Ljava/lang/String;)I"
	require.NoError(t, observe.Validate())
	enforce := validPatch()
	enforce.Descriptor = "(Ljava/lang/String;)I"
	require.Error(t, enforce.Validate())

	for name, mutate := range map[string]func(*PatchSpec){
		"unknown mode":           func(p *PatchSpec) { p.Mode = "watch" },
		"value in observe mode":  func(p *PatchSpec) { p.Value = "x" },
		"action other than none": func(p *PatchSpec) { p.Action = "throw" },
		"negative argument":      func(p *PatchSpec) { p.Predicate = &PatchPredicate{Argument: -1, Contains: "x"} },
		"argument too large":     func(p *PatchSpec) { p.Predicate = &PatchPredicate{Argument: 255, Contains: "x"} },
		"empty literal":          func(p *PatchSpec) { p.Predicate = &PatchPredicate{Argument: 0} },
		"literal too long": func(p *PatchSpec) {
			p.Predicate = &PatchPredicate{Argument: 0, Contains: strings.Repeat("x", MaxPredicateContainsBytes+1)}
		},
		"predicate while enforcing": func(p *PatchSpec) {
			p.Mode, p.Action, p.Value = PatchModeEnforce, PatchActionReturn, "x"
			p.Predicate = &PatchPredicate{Argument: 0, Contains: "x"}
		},
	} {
		patch := validPatch()
		patch.Mode, patch.Action, patch.Value = PatchModeObserve, "", ""
		mutate(&patch)
		require.Error(t, patch.Validate(), name)
	}
}

func TestRuleValidateAcceptsPatchesWithoutSpans(t *testing.T) {
	rule := DynamicInstrumentationRule{
		Service: services.GlobDefinitionCriteria{{PIDs: []uint32{1}}},
		Patches: []PatchSpec{validPatch()},
	}
	require.NoError(t, rule.Validate())

	rule.Patches = nil
	require.ErrorContains(t, rule.Validate(), "spans or patches")
}
