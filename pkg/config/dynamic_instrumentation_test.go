// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
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

func TestRuleValidateAcceptsPatchesWithoutSpans(t *testing.T) {
	rule := DynamicInstrumentationRule{
		Service: services.GlobDefinitionCriteria{{PIDs: []uint32{1}}},
		Patches: []PatchSpec{validPatch()},
	}
	require.NoError(t, rule.Validate())

	rule.Patches = nil
	require.ErrorContains(t, rule.Validate(), "spans or patches")
}
