// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/runtimemetrics"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rmlog() *slog.Logger {
	return slog.With("component", "otel.RuntimeMetricsReporter")
}

type RuntimeMetricsReporter struct {
	ctx           context.Context
	cfg           *otelcfg.MetricsConfig
	nodeMeta      meta.NodeMeta
	exporter      sdkmetric.Exporter
	reporters     otelcfg.ReporterPool[*svc.Attrs, *RuntimeMetrics]
	runtimeReader *runtimemetrics.Manager
	processEvents <-chan exec.ProcessEvent
	log           *slog.Logger
}

type RuntimeMetrics struct {
	ctx      context.Context
	service  *svc.Attrs
	provider *metric.MeterProvider

	memoryLimit       instrument.Int64Gauge
	memoryAllocated   instrument.Int64Gauge
	memoryAllocations instrument.Int64Gauge
	memoryUsed        instrument.Int64Gauge
	memoryGCGoal      instrument.Int64Gauge
	memoryGCCycles    instrument.Int64Gauge
	goroutineCount    instrument.Int64Gauge
	processorLimit    instrument.Int64Gauge
	configGOGC        instrument.Int64Gauge
}

func ReportRuntimeMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	processEvents *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() || !jointMetricsConfig.Features.AppRuntime() {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		reporter, err := newRuntimeMetricsReporter(ctx, ctxInfo, cfg, processEvents)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL runtime metrics reporter: %w", err)
		}

		return reporter.reportMetrics, nil
	}
}

func newRuntimeMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	processEventCh *msg.Queue[exec.ProcessEvent],
) (*RuntimeMetricsReporter, error) {
	log := rmlog()

	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, err
	}

	reporter := &RuntimeMetricsReporter{
		ctx:           ctx,
		cfg:           cfg,
		nodeMeta:      ctxInfo.NodeMeta,
		exporter:      instrumentMetricsExporter(ctxInfo.Metrics, exporter),
		runtimeReader: runtimemetrics.NewManager(log),
		processEvents: processEventCh.Subscribe(msg.SubscriberName("otel.RuntimeMetricsReporter.processEvents")),
		log:           log,
	}

	reporter.reporters = otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(id svc.UID, v *RuntimeMetrics) {
			llog := log.With("service", id)
			llog.Debug("evicting runtime metrics reporter from cache")

			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted runtime metrics provider", "error", err)
				}
			}()
		}, reporter.newMetricSet)

	return reporter, nil
}

func (r *RuntimeMetricsReporter) newMetricsInstance(service *svc.Attrs) RuntimeMetrics {
	log := r.log
	resourceAttributes := AppResourceAttrsForService(&r.nodeMeta, service)
	if service != nil {
		log = log.With("service", service)
	}
	log.Debug("creating new runtime metrics reporter")

	resources := resource.NewWithAttributes(semconv.SchemaURL, resourceAttributes...)
	provider := metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(r.exporter,
			metric.WithInterval(r.cfg.Interval))),
	)

	return RuntimeMetrics{
		ctx:      r.ctx,
		service:  service,
		provider: provider,
	}
}

func (r *RuntimeMetricsReporter) newMetricSet(service *svc.Attrs) (*RuntimeMetrics, error) {
	metrics := r.newMetricsInstance(service)
	meter := metrics.provider.Meter(reporterName)
	if err := setupRuntimeMeters(&metrics, meter); err != nil {
		return nil, err
	}
	return &metrics, nil
}

func setupRuntimeMeters(metrics *RuntimeMetrics, meter instrument.Meter) error {
	var err error
	metrics.memoryLimit, err = meter.Int64Gauge("go.memory.limit", instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating go memory limit: %w", err)
	}
	metrics.memoryAllocated, err = meter.Int64Gauge("go.memory.allocated", instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating go memory allocated: %w", err)
	}
	metrics.memoryAllocations, err = meter.Int64Gauge("go.memory.allocations", instrument.WithUnit("{allocation}"))
	if err != nil {
		return fmt.Errorf("creating go memory allocations: %w", err)
	}
	metrics.memoryUsed, err = meter.Int64Gauge("go.memory.used", instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating go memory used: %w", err)
	}
	metrics.memoryGCGoal, err = meter.Int64Gauge("go.memory.gc.goal", instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating go memory gc goal: %w", err)
	}
	metrics.memoryGCCycles, err = meter.Int64Gauge("go.memory.gc.cycles", instrument.WithUnit("{cycle}"))
	if err != nil {
		return fmt.Errorf("creating go memory gc cycles: %w", err)
	}
	metrics.goroutineCount, err = meter.Int64Gauge("go.goroutine.count", instrument.WithUnit("{goroutine}"))
	if err != nil {
		return fmt.Errorf("creating go goroutine count: %w", err)
	}
	metrics.processorLimit, err = meter.Int64Gauge("go.processor.limit", instrument.WithUnit("{thread}"))
	if err != nil {
		return fmt.Errorf("creating go processor limit: %w", err)
	}
	metrics.configGOGC, err = meter.Int64Gauge("go.config.gogc", instrument.WithUnit("%"))
	if err != nil {
		return fmt.Errorf("creating go config gogc: %w", err)
	}

	return nil
}

func (r *RuntimeMetricsReporter) reportMetrics(ctx context.Context) {
	defer r.close()

	interval := r.cfg.Interval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.log.Debug("context done, stopping runtime metrics reporting")
			return
		case <-ticker.C:
			r.reportRuntimeMetrics()
		case pe, ok := <-r.processEvents:
			if !ok {
				r.log.Debug("process events channel closed, stopping runtime metrics reporting")
				return
			}
			r.runtimeReader.OnProcessEvent(&pe)
		}
	}
}

func (r *RuntimeMetricsReporter) reportRuntimeMetrics() {
	if r.runtimeReader.Empty() {
		return
	}
	for _, snapshot := range r.runtimeReader.Snapshots() {
		metrics, err := r.reporters.For(&snapshot.Service)
		if err != nil {
			r.log.Debug("creating runtime metric set failed", "pid", snapshot.PID, "error", err)
			continue
		}
		recordRuntimeMetrics(r.ctx, metrics, snapshot)
	}
}

func recordRuntimeMetrics(ctx context.Context, metrics *RuntimeMetrics, snapshot runtimemetrics.Snapshot) {
	if metrics == nil {
		return
	}

	if snapshot.MemoryLimit != nil {
		metrics.memoryLimit.Record(ctx, *snapshot.MemoryLimit)
	} else {
		metrics.memoryLimit.Remove(ctx)
	}
	metrics.memoryAllocated.Record(ctx, int64(snapshot.MemoryAllocated))
	metrics.memoryAllocations.Record(ctx, int64(snapshot.MemoryAllocations))
	metrics.memoryUsed.Record(ctx, int64(snapshot.MemoryUsedStack),
		instrument.WithAttributes(attribute.String("go.memory.type", "stack")))
	metrics.memoryUsed.Record(ctx, int64(snapshot.MemoryUsedOther),
		instrument.WithAttributes(attribute.String("go.memory.type", "other")))
	metrics.memoryGCGoal.Record(ctx, int64(snapshot.MemoryGCGoal))
	metrics.memoryGCCycles.Record(ctx, int64(snapshot.GCCyclesAutomatic),
		instrument.WithAttributes(attribute.String("gc.type", "automatic")))
	if snapshot.GCCyclesForced > 0 {
		metrics.memoryGCCycles.Record(ctx, int64(snapshot.GCCyclesForced),
			instrument.WithAttributes(attribute.String("gc.type", "forced")))
	}
	metrics.goroutineCount.Record(ctx, snapshot.GoroutineCount)
	metrics.processorLimit.Record(ctx, snapshot.ProcessorLimit)
	if snapshot.GOGC != nil {
		metrics.configGOGC.Record(ctx, *snapshot.GOGC)
	} else {
		metrics.configGOGC.Remove(ctx)
	}
}

func (r *RuntimeMetricsReporter) close() {
	go func() {
		if err := r.exporter.Shutdown(r.ctx); err != nil {
			rmlog().Warn("closing runtime metrics provider", "error", err)
			return
		}
		rmlog().Debug("runtime metrics reporter closed")
	}()
}
