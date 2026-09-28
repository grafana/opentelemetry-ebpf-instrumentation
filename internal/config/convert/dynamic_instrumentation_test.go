// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
	legacyyaml "gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/config/schema"
)

func TestDynamicInstrumentationV2RoundTrip(t *testing.T) {
	cfg := defaultRuntimeConfig()
	require.NoError(t, legacyyaml.Unmarshal([]byte(`enabled: true
listen_address: 127.0.0.1:8089
symbol_cache_bytes: 123456
rules:
  - service: [{k8s_namespace: shop, k8s_pod_name: "checkout-*", k8s_service_name: checkout}]
    spans: [{name: order, on: {function_span: "main.*Order"}}]
`), &cfg.DynamicInstrumentation))
	doc, _ := RuntimeToV2(&cfg)
	data, err := yaml.Marshal(doc)
	require.NoError(t, err)
	require.Contains(t, string(data), "dynamic_instrumentation:")
	parsed, _, err := schema.ParseStandaloneYAML(data)
	require.NoError(t, err)
	restored, err := DocumentToRuntime(parsed)
	require.NoError(t, err)
	want, err := legacyyaml.Marshal(cfg.DynamicInstrumentation)
	require.NoError(t, err)
	got, err := legacyyaml.Marshal(restored.DynamicInstrumentation)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
}
