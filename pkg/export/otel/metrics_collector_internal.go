package otel

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/buildinfo"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
)

func imclog() *slog.Logger {
	return slog.With("component", "otel.InternalMetricsCollector")
}

// InternalMetricsCollector is an internal metrics collector that uses the collector SDK
type InternalMetricsCollector struct {
	ctx           context.Context
	cfg           *MetricsConfig
	ctxInfo       *global.ContextInfo
	exporter      exporter.Metrics
	lastFlushTime time.Time
	
	// Internal counters
	tracerFlushes       int64
	metricExports       int64
	metricExportErrors  int64
	traceExports        int64
	traceExportErrors   int64
	instrumentedProcesses int64
}

func NewInternalMetricsCollector(ctx context.Context, ctxInfo *global.ContextInfo, cfg *MetricsConfig) (*InternalMetricsCollector, error) {
	log := imclog()
	log.Debug("instantiating internal metrics collector")
	
	exp, err := getInternalMetricsExporter(ctx, cfg)
	if err != nil {
		log.Error("can't instantiate internal metrics exporter", "error", err)
		return nil, err
	}
	
	if err := exp.Start(ctx, nil); err != nil {
		log.Error("error starting internal metrics exporter", "error", err)
		return nil, err
	}
	
	return &InternalMetricsCollector{
		ctx:           ctx,
		cfg:           cfg,
		ctxInfo:       ctxInfo,
		exporter:      exp,
		lastFlushTime: time.Now(),
	}, nil
}

func (imc *InternalMetricsCollector) Close() error {
	return imc.exporter.Shutdown(imc.ctx)
}

// TracerFlush implements imetrics.Reporter
func (imc *InternalMetricsCollector) TracerFlush(len int) {
	imc.tracerFlushes++
	// Flush internal metrics periodically
	if time.Since(imc.lastFlushTime) >= imc.cfg.Interval {
		imc.flushInternalMetrics()
		imc.lastFlushTime = time.Now()
	}
}

// OTELMetricExport implements imetrics.Reporter
func (imc *InternalMetricsCollector) OTELMetricExport(len int) {
	imc.metricExports++
}

// OTELMetricExportError implements imetrics.Reporter
func (imc *InternalMetricsCollector) OTELMetricExportError(err error) {
	imc.metricExportErrors++
}

// OTELTraceExport implements imetrics.Reporter
func (imc *InternalMetricsCollector) OTELTraceExport(len int) {
	imc.traceExports++
}

// OTELTraceExportError implements imetrics.Reporter
func (imc *InternalMetricsCollector) OTELTraceExportError(err error) {
	imc.traceExportErrors++
}

// InstrumentedProcesses implements imetrics.Reporter
func (imc *InternalMetricsCollector) InstrumentedProcesses(len int) {
	imc.instrumentedProcesses = int64(len)
}

// InstrumentProcess implements imetrics.Reporter
func (imc *InternalMetricsCollector) InstrumentProcess(processName string) {
	// Track instrumented processes
	imc.instrumentedProcesses++
}

// UninstrumentProcess implements imetrics.Reporter
func (imc *InternalMetricsCollector) UninstrumentProcess(processName string) {
	// Track uninstrumented processes
	imc.instrumentedProcesses--
	if imc.instrumentedProcesses < 0 {
		imc.instrumentedProcesses = 0
	}
}

// PrometheusRequest implements imetrics.Reporter
func (imc *InternalMetricsCollector) PrometheusRequest(port, path string) {
	// This is used for tracking Prometheus requests, not applicable for OTLP
	// but required by the interface
}

// Start implements imetrics.Reporter
func (imc *InternalMetricsCollector) Start(ctx context.Context) {
	// Initialize if needed - the exporter is already started in the constructor
}

func (imc *InternalMetricsCollector) flushInternalMetrics() {
	metrics := imc.generateInternalMetrics()
	if metrics.MetricCount() > 0 {
		if err := imc.exporter.ConsumeMetrics(imc.ctx, metrics); err != nil {
			imclog().Error("error sending internal metrics to consumer", "error", err)
		}
	}
}

func (imc *InternalMetricsCollector) generateInternalMetrics() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	
	// Create resource scope
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	resource := resourceMetrics.Resource()
	
	// Set internal service resource attributes
	resource.Attributes().PutStr("service.name", "beyla-internal")
	resource.Attributes().PutStr("service.version", buildinfo.Version)
	resource.Attributes().PutStr("telemetry.sdk.language", "go")
	resource.Attributes().PutStr("telemetry.sdk.name", "beyla")
	resource.Attributes().PutStr("telemetry.sdk.version", buildinfo.Version)
	
	if imc.ctxInfo.HostID != "" {
		resource.Attributes().PutStr("host.id", imc.ctxInfo.HostID)
	}
	
	// Add extra resource attributes
	for _, attr := range imc.ctxInfo.ExtraResourceAttributes {
		resource.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
	}

	// Create instrumentation scope
	scopeMetrics := resourceMetrics.ScopeMetrics().AppendEmpty()
	scopeMetrics.Scope().SetName("beyla_internal")
	
	// Generate various internal metrics
	imc.generateTracerFlushesMetric(scopeMetrics)
	imc.generateMetricExportMetrics(scopeMetrics)
	imc.generateTraceExportMetrics(scopeMetrics)
	imc.generateInstrumentedProcessesMetric(scopeMetrics)
	imc.generateBeylaInfoMetric(scopeMetrics)
	
	return metrics
}

func (imc *InternalMetricsCollector) generateTracerFlushesMetric(scopeMetrics pmetric.ScopeMetrics) {
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName("beyla.ebpf.tracer.flushes")
	metric.SetUnit("1")
	metric.SetDescription("Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage")
	
	histogram := metric.SetEmptyHistogram()
	histogram.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	
	dp := histogram.DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.SetCount(uint64(imc.tracerFlushes))
	dp.SetSum(float64(imc.tracerFlushes))		// Use default buckets
		buckets := []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0}
		explicitBounds := dp.ExplicitBounds()
		explicitBounds.FromRaw(buckets)
		
		// Set all bucket counts to the total count (simplified)
		bucketCounts := make([]uint64, len(buckets)+1)
		bucketCounts[len(buckets)] = uint64(imc.tracerFlushes)
		bucketCountsSlice := dp.BucketCounts()
		bucketCountsSlice.FromRaw(bucketCounts)
}

func (imc *InternalMetricsCollector) generateMetricExportMetrics(scopeMetrics pmetric.ScopeMetrics) {
	// Metric exports counter
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName("beyla.otel.metric.exports")
	metric.SetUnit("1")
	metric.SetDescription("Number of metric exports")
	
	sum := metric.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	sum.SetIsMonotonic(true)
	
	dp := sum.DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.SetIntValue(imc.metricExports)
	
	// Metric export errors counter
	errorMetric := scopeMetrics.Metrics().AppendEmpty()
	errorMetric.SetName("beyla.otel.metric.export.errors")
	errorMetric.SetUnit("1")
	errorMetric.SetDescription("Number of metric export errors")
	
	errorSum := errorMetric.SetEmptySum()
	errorSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	errorSum.SetIsMonotonic(true)
	
	errorDp := errorSum.DataPoints().AppendEmpty()
	errorDp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	errorDp.SetIntValue(imc.metricExportErrors)
}

func (imc *InternalMetricsCollector) generateTraceExportMetrics(scopeMetrics pmetric.ScopeMetrics) {
	// Trace exports counter
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName("beyla.otel.trace.exports")
	metric.SetUnit("1")
	metric.SetDescription("Number of trace exports")
	
	sum := metric.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	sum.SetIsMonotonic(true)
	
	dp := sum.DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.SetIntValue(imc.traceExports)
	
	// Trace export errors counter
	errorMetric := scopeMetrics.Metrics().AppendEmpty()
	errorMetric.SetName("beyla.otel.trace.export.errors")
	errorMetric.SetUnit("1")
	errorMetric.SetDescription("Number of trace export errors")
	
	errorSum := errorMetric.SetEmptySum()
	errorSum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	errorSum.SetIsMonotonic(true)
	
	errorDp := errorSum.DataPoints().AppendEmpty()
	errorDp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	errorDp.SetIntValue(imc.traceExportErrors)
}

func (imc *InternalMetricsCollector) generateInstrumentedProcessesMetric(scopeMetrics pmetric.ScopeMetrics) {
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName("beyla.instrumented.processes")
	metric.SetUnit("1")
	metric.SetDescription("Number of processes instrumented by Beyla")
	
	gauge := metric.SetEmptyGauge()
	
	dp := gauge.DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.SetIntValue(imc.instrumentedProcesses)
}

func (imc *InternalMetricsCollector) generateBeylaInfoMetric(scopeMetrics pmetric.ScopeMetrics) {
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName("beyla.build.info")
	metric.SetUnit("1")
	metric.SetDescription("Beyla build information")
	
	gauge := metric.SetEmptyGauge()
	
	dp := gauge.DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	dp.SetIntValue(1)
	
	// Add build info as attributes
	dp.Attributes().PutStr("version", buildinfo.Version)
	dp.Attributes().PutStr("revision", buildinfo.Revision)
	dp.Attributes().PutStr("go_version", runtime.Version())
}

func getInternalMetricsExporter(ctx context.Context, cfg *MetricsConfig) (exporter.Metrics, error) {
	switch proto := cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "":
		return createInternalHTTPMetricsExporter(ctx, cfg)
	case ProtocolGRPC:
		return createInternalGRPCMetricsExporter(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func createInternalHTTPMetricsExporter(ctx context.Context, cfg *MetricsConfig) (exporter.Metrics, error) {
	slog.Debug("instantiating HTTP InternalMetricsCollector", "protocol", cfg.GetProtocol())
	
	opts, err := getHTTPMetricEndpointOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("can't get HTTP metrics endpoint options: %w", err)
	}
	
	factory := otlphttpexporter.NewFactory()
	config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
	
	// Configure the exporter
	config.ClientConfig = confighttp.ClientConfig{
		Endpoint: opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
		TLS: configtls.ClientConfig{
			Insecure:           opts.Insecure,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		Headers: convertInternalHeaders(opts.Headers),
	}
	
	set := getInternalMetricsSettings(factory.Type())
	exporter, err := factory.CreateMetrics(ctx, set, config)
	if err != nil {
		return nil, fmt.Errorf("can't create OTLP HTTP internal metrics exporter: %w", err)
	}
	
	return exporterhelper.NewMetrics(ctx, set, cfg,
		exporter.ConsumeMetrics,
		exporterhelper.WithStart(exporter.Start),
		exporterhelper.WithShutdown(exporter.Shutdown),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
	)
}

func createInternalGRPCMetricsExporter(ctx context.Context, cfg *MetricsConfig) (exporter.Metrics, error) {
	slog.Debug("instantiating GRPC InternalMetricsCollector", "protocol", cfg.GetProtocol())
	
	opts, err := getGRPCMetricEndpointOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("can't get GRPC metrics endpoint options: %w", err)
	}
	
	endpoint, _, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return nil, fmt.Errorf("can't parse metrics endpoint: %w", err)
	}
	
	factory := otlpexporter.NewFactory()
	config := factory.CreateDefaultConfig().(*otlpexporter.Config)
	
	// Configure the exporter
	config.ClientConfig = configgrpc.ClientConfig{
		Endpoint: endpoint.String(),
		TLS: configtls.ClientConfig{
			Insecure:           opts.Insecure,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		Headers: convertInternalHeaders(opts.Headers),
	}
	
	set := getInternalMetricsSettings(factory.Type())
	exporter, err := factory.CreateMetrics(ctx, set, config)
	if err != nil {
		return nil, fmt.Errorf("can't create OTLP GRPC internal metrics exporter: %w", err)
	}
	
	return exporterhelper.NewMetrics(ctx, set, cfg,
		exporter.ConsumeMetrics,
		exporterhelper.WithStart(exporter.Start),
		exporterhelper.WithShutdown(exporter.Shutdown),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
	)
}

func getInternalMetricsSettings(componentType component.Type) exporter.Settings {
	logger, _ := zap.NewDevelopment()
	return exporter.Settings{
		ID:                component.NewID(componentType),
		TelemetrySettings: component.TelemetrySettings{Logger: logger},
		BuildInfo:         component.NewDefaultBuildInfo(),
	}
}

func convertInternalHeaders(headers map[string]string) map[string]configopaque.String {
	result := make(map[string]configopaque.String)
	for k, v := range headers {
		result[k] = configopaque.String(v)
	}
	return result
}

// Ensure InternalMetricsCollector implements the imetrics.Reporter interface
var _ imetrics.Reporter = (*InternalMetricsCollector)(nil)
