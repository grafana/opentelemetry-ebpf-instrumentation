// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testStatMetricsTCPRtt(t *testing.T, port string) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Observations should appear above the 100ms bucket (pumba injects 100ms delay)
		bucketAt100ms, err := pq.Query(`obi_stat_tcp_rtt_seconds_bucket{dst_port="` + port + `",le="0.1"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, bucketAt100ms)

		countResults, err := pq.Query(`obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, countResults)

		// if pumba is working, not all observations fit in the <=100ms bucket
		assert.Less(ct, totalPromCount(ct, bucketAt100ms), totalPromCount(ct, countResults))
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPRttGo(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsTCP(t, testCaseURL)
			testStatMetricsTCPRtt(t, "8080")
		})
	}
}

func testStatMetricsTCPFailedConnectionGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_failed_connections{dst_port="19999"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.Positive(ct, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}

type runtimeMetricExpectation struct {
	obiName     string
	promName    string
	obiLabels   map[string]string
	promLabels  map[string]string
	exact       bool
	positive    bool
	description string
}

func testRuntimeMetricsGoPrometheusCoverage(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	expected := []runtimeMetricExpectation{
		{obiName: "go_memory_limit_bytes", promName: "go_gc_gomemlimit_bytes", exact: true, positive: true, description: "configured memory limit"},
		{obiName: "go_memory_allocated_bytes", promName: "go_memstats_alloc_bytes_total", positive: true, description: "heap allocation"},
		{obiName: "go_memory_allocations_total", promName: "go_memstats_mallocs_total", positive: true, description: "heap allocation count"},
		{
			obiName:     "go_memory_gc_cycles_total",
			obiLabels:   map[string]string{"gc_type": "automatic"},
			promName:    "go_gc_cycles_automatic_gc_cycles_total",
			description: "automatic GC cycle count",
		},
		{
			obiName:     "go_memory_gc_cycles_total",
			obiLabels:   map[string]string{"gc_type": "forced"},
			promName:    "go_gc_cycles_forced_gc_cycles_total",
			positive:    true,
			description: "forced GC cycle count",
		},
		{obiName: "go_goroutine_count", promName: "go_goroutines", positive: true, description: "goroutine count"},
		{obiName: "go_processor_limit", promName: "go_sched_gomaxprocs_threads", exact: true, positive: true, description: "GOMAXPROCS"},
		{obiName: "go_config_gogc_percent", promName: "go_gc_gogc_percent", exact: true, positive: true, description: "GOGC"},
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		directMetrics, err := promtest.Scrape("http://localhost:8382/metrics")
		require.NoError(ct, err)

		for _, metric := range expected {
			directMetric, ok := promtest.FindMetric(directMetrics, metric.promName, metric.promLabels)
			require.Truef(ct, ok, "service /metrics missing %s (%s)", metric.promName, metric.description)
			if metric.positive {
				assert.Positivef(ct, directMetric.Value, "service /metrics %s should be positive", metric.promName)
			}

			results, err := pq.Query(runtimeMetricQuery(metric))
			require.NoError(ct, err)
			require.Lenf(ct, results, 1, "expected one OBI runtime metric series for %s", metric.obiName)
			obiValue := promResultValue(ct, results[0])
			if metric.positive {
				assert.Positivef(ct, obiValue, "OBI %s should be positive", metric.obiName)
			}
			if metric.exact {
				assert.InDeltaf(ct, directMetric.Value, obiValue, 0.5,
					"OBI %s should match service /metrics %s", metric.obiName, metric.promName)
			}
		}
	}, testTimeout, 250*time.Millisecond)
}

func runtimeMetricQuery(metric runtimeMetricExpectation) string {
	labels := `service_name="testserver",service_namespace="integration-test",telemetry_sdk_language="go"`
	for name, value := range metric.obiLabels {
		labels += fmt.Sprintf(`,%s="%s"`, name, value)
	}
	return fmt.Sprintf(`%s{%s}`, metric.obiName, labels)
}

func promResultValue(t require.TestingT, result promtest.Result) float64 {
	require.Len(t, result.Value, 2)
	value, err := strconv.ParseFloat(result.Value[1].(string), 64)
	require.NoError(t, err)
	return value
}
