// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/runtimemetrics"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type runtimeMetricsReporter struct {
	cfg         *PrometheusConfig
	promConnect *connector.PrometheusManager

	nodeMeta            meta.NodeMeta
	kubeEnabled         bool
	dockerEnabled       bool
	extraMetadataLabels []attr.Name

	serviceMap      map[svc.UID]svc.Attrs
	pidsTracker     otel.PidServiceTracker
	runtimeReader   *runtimemetrics.Manager
	processEvents   <-chan exec.ProcessEvent
	memoryLimit     *prometheus.GaugeVec
	memoryAllocated *prometheus.GaugeVec

	memoryAllocations *prometheus.GaugeVec
	memoryGCCycles    *prometheus.GaugeVec
	goroutineCount    *prometheus.GaugeVec
	processorLimit    *prometheus.GaugeVec
	configGOGC        *prometheus.GaugeVec
}

func RuntimePrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	processEvents *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() || !jointMetricsConfig.Features.AppRuntime() {
			return swarm.EmptyRunFunc()
		}

		reporter := newRuntimeMetricsReporter(ctx, ctxInfo, cfg, processEvents)
		if cfg.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newRuntimeMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	processEventCh *msg.Queue[exec.ProcessEvent],
) *runtimeMetricsReporter {
	kubeEnabled := ctxInfo.K8sInformer.IsKubeEnabled()
	dockerEnabled := ctxInfo.DockerMetadata.IsEnabled(ctx)
	extraMetadataLabels := parseExtraMetadata(cfg.ExtraResourceLabels)

	runtimeLabelNames := labelNamesTargetInfo(kubeEnabled, dockerEnabled, &ctxInfo.NodeMeta, extraMetadataLabels)
	runtimeGCLabelNames := append(append([]string{}, runtimeLabelNames...), "gc_type")

	reporter := &runtimeMetricsReporter{
		cfg:                 cfg,
		promConnect:         ctxInfo.Prometheus,
		nodeMeta:            ctxInfo.NodeMeta,
		kubeEnabled:         kubeEnabled,
		dockerEnabled:       dockerEnabled,
		extraMetadataLabels: extraMetadataLabels,
		serviceMap:          map[svc.UID]svc.Attrs{},
		pidsTracker:         otel.NewPidServiceTracker(),
		runtimeReader:       runtimemetrics.NewManager(slog.With("component", "prom.RuntimeMetricsReporter")),
		processEvents:       processEventCh.Subscribe(msg.SubscriberName("prom.RuntimeMetricsReporter.processEvents")),
		memoryLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_memory_limit_bytes",
			Help: "Runtime memory limit configured by the user, if a limit exists.",
		}, runtimeLabelNames),
		memoryAllocated: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_memory_allocated_bytes",
			Help: "Memory allocated to the heap by the application.",
		}, runtimeLabelNames),
		memoryAllocations: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_memory_allocations_total",
			Help: "Count of allocations to the heap by the application.",
		}, runtimeLabelNames),
		memoryGCCycles: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_memory_gc_cycles_total",
			Help: "Count of completed Go garbage collection cycles.",
		}, runtimeGCLabelNames),
		goroutineCount: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_goroutine_count",
			Help: "Count of live goroutines.",
		}, runtimeLabelNames),
		processorLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_processor_limit",
			Help: "The number of OS threads that can execute user-level Go code simultaneously.",
		}, runtimeLabelNames),
		configGOGC: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "go_config_gogc_percent",
			Help: "Heap size target percentage configured by the user, otherwise 100.",
		}, runtimeLabelNames),
	}

	collectors := []prometheus.Collector{
		reporter.memoryLimit,
		reporter.memoryAllocated,
		reporter.memoryAllocations,
		reporter.memoryGCCycles,
		reporter.goroutineCount,
		reporter.processorLimit,
		reporter.configGOGC,
	}

	if cfg.Registry != nil {
		cfg.Registry.MustRegister(collectors...)
	} else {
		reporter.promConnect.Register(cfg.Port, cfg.Path, collectors...)
	}

	return reporter
}

func (r *runtimeMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *runtimeMetricsReporter) collectMetrics(ctx context.Context) {
	interval := 10 * time.Second
	if r.cfg.TTL > 0 && r.cfg.TTL < interval {
		interval = r.cfg.TTL
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collectRuntimeMetrics()
		case pe, ok := <-r.processEvents:
			if !ok {
				return
			}
			r.handleProcessEvent(&pe)
		}
	}
}

func (r *runtimeMetricsReporter) collectRuntimeMetrics() {
	if r.runtimeReader.Empty() {
		return
	}

	for _, snapshot := range r.runtimeReader.Snapshots() {
		labels := r.labelValuesTargetInfo(&snapshot.Service)
		if snapshot.MemoryLimit != nil {
			r.memoryLimit.WithLabelValues(labels...).Set(float64(*snapshot.MemoryLimit))
		} else {
			r.memoryLimit.DeleteLabelValues(labels...)
		}
		r.memoryAllocated.WithLabelValues(labels...).Set(float64(snapshot.MemoryAllocated))
		r.memoryAllocations.WithLabelValues(labels...).Set(float64(snapshot.MemoryAllocations))
		r.memoryGCCycles.WithLabelValues(append(labels, "automatic")...).Set(float64(snapshot.GCCyclesAutomatic))
		if snapshot.GCCyclesForced > 0 {
			r.memoryGCCycles.WithLabelValues(append(labels, "forced")...).Set(float64(snapshot.GCCyclesForced))
		}
		r.goroutineCount.WithLabelValues(labels...).Set(float64(snapshot.GoroutineCount))
		r.processorLimit.WithLabelValues(labels...).Set(float64(snapshot.ProcessorLimit))
		r.configGOGC.WithLabelValues(labels...).Set(float64(snapshot.GOGC))
	}
}

func (r *runtimeMetricsReporter) handleProcessEvent(pe *exec.ProcessEvent) {
	r.runtimeReader.OnProcessEvent(pe)
	if pe == nil || pe.File == nil {
		return
	}

	uid := pe.File.Service.UID
	if pe.Type == exec.ProcessEventCreated {
		if staleUID, exists := r.pidsTracker.TracksPID(pe.File.Pid); exists && !staleUID.Equals(&uid) {
			r.pidsTracker.ReplaceUID(staleUID, uid)
			if origAttrs, ok := r.serviceMap[staleUID]; ok {
				r.deleteRuntimeMetrics(&origAttrs)
				delete(r.serviceMap, staleUID)
				r.serviceMap[uid] = pe.File.Service
			}
			return
		}

		if origAttrs, ok := r.serviceMap[uid]; ok {
			r.deleteRuntimeMetrics(&origAttrs)
		}
		r.serviceMap[uid] = pe.File.Service
		r.pidsTracker.AddPID(pe.File.Pid, uid)
		return
	}

	if deleted, origUID := r.pidsTracker.RemovePID(pe.File.Pid); deleted {
		if origAttrs, ok := r.serviceMap[origUID]; ok {
			r.deleteRuntimeMetrics(&origAttrs)
		}
		delete(r.serviceMap, origUID)
	}
}

func (r *runtimeMetricsReporter) labelValuesTargetInfo(service *svc.Attrs) []string {
	return labelValuesTargetInfo(service, &r.nodeMeta, r.kubeEnabled, r.dockerEnabled, r.extraMetadataLabels)
}

func (r *runtimeMetricsReporter) deleteRuntimeMetrics(service *svc.Attrs) {
	if service == nil {
		return
	}

	labels := r.labelValuesTargetInfo(service)
	r.memoryLimit.DeleteLabelValues(labels...)
	r.memoryAllocated.DeleteLabelValues(labels...)
	r.memoryAllocations.DeleteLabelValues(labels...)
	r.memoryGCCycles.DeleteLabelValues(append(labels, "automatic")...)
	r.memoryGCCycles.DeleteLabelValues(append(labels, "forced")...)
	r.goroutineCount.DeleteLabelValues(labels...)
	r.processorLimit.DeleteLabelValues(labels...)
	r.configGOGC.DeleteLabelValues(labels...)
}
