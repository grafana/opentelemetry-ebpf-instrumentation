// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestDynamicInvocationPrometheusLifecycle(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)
	service := svc.Attrs{UID: svc.UID{Name: "checkout", Namespace: "shop", Instance: "instance"}, SDKLanguage: svc.InstrumentableGolang, Metadata: map[attr.Name]string{
		attr.K8sPodName: "checkout-1", attr.K8sPodUID: "pod-uid", attr.K8sNamespaceName: "store", attr.K8sDeploymentName: "checkout", attr.K8sNodeName: "worker-1", attr.K8sClusterName: "cluster",
	}}
	var count uint64
	var readErr error
	probe := &DynamicProbeCounter{PID: 123, Function: "main.order", Service: func() svc.Attrs { return service }, Read: func() (uint64, error) { return count, readErr }}
	reporter.DynamicProbeInvocations(1, probe)
	gather := func() []*dto.Metric {
		t.Helper()
		metrics, err := registry.Gather()
		require.NoError(t, err)
		for _, family := range metrics {
			if family.GetName() == "obi_dynamic_function_invocations_total" {
				require.Equal(t, dto.MetricType_COUNTER, family.GetType())
				return family.Metric
			}
		}
		return nil
	}
	records := gather()
	require.Len(t, records, 1)
	require.Zero(t, records[0].GetCounter().GetValue())
	labels := metricLabels(records[0])
	require.Equal(t, "123", labels["process_pid"])
	require.Equal(t, "main.order", labels["code_function_name"])
	require.Equal(t, "checkout", labels["service_name"])
	require.Equal(t, "shop", labels["service_namespace"])
	require.Equal(t, "instance", labels["service_instance_id"])
	require.Equal(t, "go", labels["telemetry_sdk_language"])
	require.Equal(t, "checkout-1", labels["k8s_pod_name"])
	require.Equal(t, "pod-uid", labels["k8s_pod_uid"])
	require.Equal(t, "store", labels["k8s_namespace_name"])
	require.Equal(t, "checkout", labels["k8s_deployment_name"])
	require.Equal(t, "worker-1", labels["k8s_node_name"])
	require.Equal(t, "cluster", labels["k8s_cluster_name"])
	require.Empty(t, labels["k8s_job_name"])
	count = 7
	service.UID.Name = "sdk-checkout"
	service.Metadata[attr.K8sPodName] = "checkout-2"
	records = gather()
	require.Len(t, records, 1, "metadata updates must not retain old labels")
	require.InDelta(t, 7, records[0].GetCounter().GetValue(), 0.001)
	require.Equal(t, "sdk-checkout", metricLabels(records[0])["service_name"])
	require.Equal(t, "checkout-2", metricLabels(records[0])["k8s_pod_name"])
	// Distinct attachments to the same address/function must be distinguishable.
	reporter.DynamicProbeInvocations(2, probe)
	require.Len(t, gather(), 2)
	reporter.DynamicProbeInvocations(1, nil)
	require.Len(t, gather(), 1)
	readErr = errors.New("map closed")
	require.Empty(t, gather(), "failed reads must not invent zero hits")
	reporter.DynamicProbeInvocations(2, nil)
	require.Empty(t, gather())
	require.Empty(t, reporter.probes, "removal must release readers and metadata")
	count, readErr = 0, nil
	reporter.DynamicProbeInvocations(3, probe)
	require.Zero(t, gather()[0].GetCounter().GetValue())
}

func TestDynamicInvocationConcurrentRemoval(t *testing.T) {
	var counters DynamicProbeCounters
	var count atomic.Uint64
	probe := &DynamicProbeCounter{PID: 1, Function: "main.work", Service: func() svc.Attrs { return svc.Attrs{} }, Read: func() (uint64, error) { return count.Load(), nil }}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 100 {
			counters.DynamicProbeInvocations(1, probe)
			count.Add(1)
			counters.DynamicProbeInvocations(1, nil)
		}
	})
	workers.Go(func() {
		for range 100 {
			counters.CollectDynamicProbes(false)
		}
	})
	workers.Wait()
	require.Empty(t, counters.CollectDynamicProbes(false))
	require.Empty(t, counters.probes)
}
