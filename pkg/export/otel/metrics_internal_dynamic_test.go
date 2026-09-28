// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestDynamicInvocationProducerLifecycle(t *testing.T) {
	for _, temporality := range []metricdata.Temporality{metricdata.CumulativeTemporality, metricdata.DeltaTemporality} {
		t.Run(temporality.String(), func(t *testing.T) {
			producer := &dynamicInvocationProducer{name: attributes.NewInternalMetrics("obi").DynamicFunctionInvocations, temporality: temporality}
			var count uint64
			service := svc.Attrs{UID: svc.UID{Name: "checkout"}, Metadata: map[attr.Name]string{attr.K8sPodName: "checkout-1"}}
			probe := &imetrics.DynamicProbeCounter{PID: 123, Function: "main.work", Read: func() (uint64, error) { return count, nil }, Service: func() svc.Attrs { return service }}
			producer.DynamicProbeInvocations(1, probe)
			collect := func() metricdata.DataPoint[int64] {
				t.Helper()
				scopes, err := producer.Produce(t.Context())
				require.NoError(t, err)
				require.Len(t, scopes, 1)
				require.Equal(t, internalMetricsMeterName, scopes[0].Scope.Name)
				metric := scopes[0].Metrics[0]
				require.Equal(t, "obi.dynamic.function.invocations", metric.Name)
				require.Equal(t, "{invocation}", metric.Unit)
				sum := metric.Data.(metricdata.Sum[int64])
				require.True(t, sum.IsMonotonic)
				require.Equal(t, temporality, sum.Temporality)
				require.Len(t, sum.DataPoints, 1)
				return sum.DataPoints[0]
			}
			first := collect()
			require.Zero(t, first.Value)
			count = 7
			require.Equal(t, int64(7), collect().Value)
			count = 9
			// Updating metadata retains the attachment count but never replays delta hits.
			service.UID.Name = "sdk-checkout"
			service.Metadata[attr.K8sPodName] = "checkout-2"
			producer.DynamicProbeInvocations(1, probe)
			point := collect()
			expected := int64(9)
			if temporality == metricdata.DeltaTemporality {
				expected = 2
			}
			require.Equal(t, expected, point.Value)
			pod, _ := point.Attributes.Value(attribute.Key("k8s.pod.name"))
			require.Equal(t, "checkout-2", pod.AsString())
			pid, _ := point.Attributes.Value(attribute.Key("process.pid"))
			require.Equal(t, int64(123), pid.AsInt64())
			producer.DynamicProbeInvocations(1, nil)
			scopes, err := producer.Produce(t.Context())
			require.NoError(t, err)
			require.Empty(t, scopes)
			count = 0
			producer.DynamicProbeInvocations(2, probe)
			replacement := collect()
			require.Zero(t, replacement.Value)
			require.True(t, replacement.StartTime.After(first.StartTime))
		})
	}
}

func TestInternalMetricsExportsDynamicInvocations(t *testing.T) {
	records := make(chan collector.MetricRecord, 64)
	cfg := &otelcfg.MetricsConfig{Interval: 10 * time.Millisecond, MetricsConsumer: testMetricsConsumer(records)}
	ctxInfo := &global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}}
	reporter, err := NewInternalMetricsReporter(t.Context(), ctxInfo, cfg, &imetrics.InternalMetricsConfig{})
	require.NoError(t, err)
	var count atomic.Uint64
	count.Store(42)
	reporter.DynamicProbeInvocations(1, &imetrics.DynamicProbeCounter{PID: 123, Function: "main.work", Service: func() svc.Attrs {
		return svc.Attrs{UID: svc.UID{Name: "checkout", Namespace: "shop"}, Metadata: map[attr.Name]string{attr.K8sPodName: "checkout-1"}}
	}, Read: func() (uint64, error) { return count.Load(), nil }})
	exported := readMetricsByName(t, records, time.Second, "obi.dynamic.function.invocations")
	require.Len(t, exported, 1)
	require.Equal(t, int64(42), exported[0].IntVal)
	require.Equal(t, "123", exported[0].Attributes["process.pid"])
	require.Equal(t, "checkout", exported[0].Attributes["service.name"])
	require.Equal(t, "checkout-1", exported[0].Attributes["k8s.pod.name"])
	reporter.DynamicProbeInvocations(1, nil)
}
