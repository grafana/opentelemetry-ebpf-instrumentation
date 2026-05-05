// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestStat_GoStatMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-stat-metrics.yml", path.Join(pathOutput, "test-suite-go-stat-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8381:8080`, `OTEL_EBPF_CONFIG_SUFFIX=-go-stat-metrics`, `PROM_CONFIG_SUFFIX=-promscrape`)
	require.NoError(t, compose.Up())
	t.Run("Go Stat Metrics TCP RTT tests", testStatMetricsTCPRttGo)
	t.Run("Go Stat Metrics TCP Failed Connection tests", testStatMetricsTCPFailedConnectionGo)
	t.Run("Go Runtime Metrics Prometheus coverage", testRuntimeMetricsGoPrometheusCoverage)
	require.NoError(t, compose.Close())
}
