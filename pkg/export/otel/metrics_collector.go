package otel

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/expire"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/instrumentations"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/otel/metric/api/metric"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

// MetricsReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
// This function creates a metrics receiver that uses the collector SDK instead of the OTEL SDK.
func MetricsReceiver(
	ctxInfo *global.ContextInfo,
	cfg *MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}

		mr := makeMetricsReceiver(ctx, ctxInfo, cfg, selectorCfg, input, processEventCh)
		return mr.provideLoop, nil
	}
}

type metricsOTELReceiver struct {
	ctx                context.Context
	cfg                *MetricsConfig
	ctxInfo            *global.ContextInfo
	selectorCfg        *attributes.SelectorConfig
	attributes         *attributes.AttrSelector
	is                 instrumentations.InstrumentationSelection
	hostID             string
	userAttribSelection attributes.Selection
	input              <-chan []request.Span
	processEvents      <-chan exec.ProcessEvent
	
	// user-selected fields for each of the reported metrics
	attrHTTPDuration           []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientDuration     []attributes.Field[*request.Span, attribute.KeyValue]
	attrGRPCServer             []attributes.Field[*request.Span, attribute.KeyValue]
	attrGRPCClient             []attributes.Field[*request.Span, attribute.KeyValue]
	attrDBClient               []attributes.Field[*request.Span, attribute.KeyValue]
	attrMessagingPublish       []attributes.Field[*request.Span, attribute.KeyValue]
	attrMessagingProcess       []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPRequestSize        []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPResponseSize       []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientRequestSize  []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientResponseSize []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelCalls         []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelGridSize      []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelBlockSize     []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUMemoryAllocations   []attributes.Field[*request.Span, attribute.KeyValue]
}

func makeMetricsReceiver(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) *metricsOTELReceiver {
	attribProvider, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, selectorCfg)
	if err != nil {
		slog.Error("error creating attribute selector", "error", err)
		return nil
	}

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	mr := &metricsOTELReceiver{
		ctx:                 ctx,
		cfg:                 cfg,
		ctxInfo:             ctxInfo,
		selectorCfg:         selectorCfg,
		attributes:          attribProvider,
		is:                  is,
		hostID:              ctxInfo.HostID,
		userAttribSelection: selectorCfg.SelectionCfg,
		input:               input.Subscribe(),
		processEvents:       processEventCh.Subscribe(),
	}

	// initialize attribute getters (same as in the original implementation)
	if is.HTTPEnabled() {
		mr.attrHTTPDuration = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPServerDuration))
		mr.attrHTTPClientDuration = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPClientDuration))
		mr.attrHTTPRequestSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPServerRequestSize))
		mr.attrHTTPResponseSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPServerResponseSize))
		mr.attrHTTPClientRequestSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPClientRequestSize))
		mr.attrHTTPClientResponseSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPClientResponseSize))
	}

	if is.GRPCEnabled() {
		mr.attrGRPCServer = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.RPCServerDuration))
		mr.attrGRPCClient = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.RPCClientDuration))
	}

	if is.DBEnabled() {
		mr.attrDBClient = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.DBClientDuration))
	}

	if is.MQEnabled() {
		mr.attrMessagingPublish = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.MessagingPublishDuration))
		mr.attrMessagingProcess = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.MessagingProcessDuration))
	}

	if is.GPUEnabled() {
		mr.attrGPUKernelCalls = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.GPUKernelLaunchCalls))
		mr.attrGPUKernelGridSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.GPUKernelGridSize))
		mr.attrGPUKernelBlockSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.GPUKernelBlockSize))
		mr.attrGPUMemoryAllocations = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.GPUMemoryAllocations))
	}

	return mr
}

func (mr *metricsOTELReceiver) provideLoop(ctx context.Context) {
	exp, err := getMetricsExporter(ctx, mr.cfg)
	if err != nil {
		slog.Error("error creating metrics exporter", "error", err)
		return
	}
	defer func() {
		err := exp.Shutdown(ctx)
		if err != nil {
			slog.Error("error shutting down metrics exporter", "error", err)
		}
	}()

	err = exp.Start(ctx, nil)
	if err != nil {
		slog.Error("error starting metrics exporter", "error", err)
		return
	}

	for spans := range mr.input {
		mr.processSpans(ctx, exp, spans)
	}
}

func (mr *metricsOTELReceiver) processSpans(ctx context.Context, exp exporter.Metrics, spans []request.Span) {
	// Group spans by service for processing
	spanGroups := make(map[svc.UID][]request.Span)
	for _, span := range spans {
		uid := span.Service.UID
		if spanGroups[uid] == nil {
			spanGroups[uid] = []request.Span{}
		}
		spanGroups[uid] = append(spanGroups[uid], span)
	}

	// Process each service group
	for uid, serviceSpans := range spanGroups {
		if len(serviceSpans) == 0 {
			continue
		}

		// Generate metrics for this service
		metrics := mr.generateMetrics(serviceSpans)
		if metrics.MetricCount() > 0 {
			err := exp.ConsumeMetrics(ctx, metrics)
			if err != nil {
				slog.Error("error sending metrics to consumer", "error", err, "service", uid)
			}
		}
	}
}

func (mr *metricsOTELReceiver) generateMetrics(spans []request.Span) pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	
	if len(spans) == 0 {
		return metrics
	}

	// Get the first span to determine service information
	firstSpan := spans[0]
	service := firstSpan.Service
	
	// Create resource scope
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	resource := resourceMetrics.Resource()
	
	// Set resource attributes from service
	envResourceAttrs := ResourceAttrsFromEnv(&service)
	for _, attr := range envResourceAttrs {
		resource.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
	}
	
	// Add host ID if available
	if mr.hostID != "" {
		resource.Attributes().PutStr("host.id", mr.hostID)
	}
	
	// Add extra resource attributes
	for _, attr := range mr.ctxInfo.ExtraResourceAttributes {
		resource.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
	}

	// Create instrumentation scope
	scopeMetrics := resourceMetrics.ScopeMetrics().AppendEmpty()
	scopeMetrics.Scope().SetName(reporterName)
	
	// Generate HTTP metrics if enabled
	if mr.is.HTTPEnabled() {
		mr.generateHTTPMetrics(scopeMetrics, spans)
	}
	
	// Generate GRPC metrics if enabled
	if mr.is.GRPCEnabled() {
		mr.generateGRPCMetrics(scopeMetrics, spans)
	}
	
	// Generate DB metrics if enabled
	if mr.is.DBEnabled() {
		mr.generateDBMetrics(scopeMetrics, spans)
	}
	
	// Generate messaging metrics if enabled
	if mr.is.MQEnabled() {
		mr.generateMessagingMetrics(scopeMetrics, spans)
	}
	
	// Generate GPU metrics if enabled
	if mr.is.GPUEnabled() {
		mr.generateGPUMetrics(scopeMetrics, spans)
	}

	return metrics
}

func (mr *metricsOTELReceiver) generateHTTPMetrics(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Filter HTTP spans
	httpSpans := make([]request.Span, 0, len(spans))
	for _, span := range spans {
		if span.Type == request.EventTypeHTTP || span.Type == request.EventTypeHTTPClient {
			httpSpans = append(httpSpans, span)
		}
	}
	
	if len(httpSpans) == 0 {
		return
	}

	// Generate HTTP duration histogram
	mr.generateHTTPDurationHistogram(scopeMetrics, httpSpans)
	
	// Generate HTTP request/response size histograms
	mr.generateHTTPSizeHistograms(scopeMetrics, httpSpans)
}

func (mr *metricsOTELReceiver) generateHTTPDurationHistogram(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Create histogram metric
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName("http_server_duration")
	metric.SetUnit("s")
	metric.SetDescription("HTTP server request duration")
	
	histogram := metric.SetEmptyHistogram()
	histogram.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	
	// Group spans by attributes for histogram buckets
	spanGroups := make(map[string][]request.Span)
	for _, span := range spans {
		if span.Type == request.EventTypeHTTP { // Only server spans for HTTP duration
			// Get attributes for this span
			attrs := mr.getHTTPAttributes(&span)
			key := mr.attributesToKey(attrs)
			spanGroups[key] = append(spanGroups[key], span)
		}
	}
	
	// Create histogram data points
	for _, groupSpans := range spanGroups {
		if len(groupSpans) == 0 {
			continue
		}
		
		dp := histogram.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
		
		// Set attributes from the first span in group
		attrs := mr.getHTTPAttributes(&groupSpans[0])
		for _, attr := range attrs {
			dp.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
		}
		
		// Calculate histogram buckets and values
		durations := make([]float64, len(groupSpans))
		for i, span := range groupSpans {
			timings := span.Timings()
			durations[i] = timings.End.Sub(timings.Start).Seconds()
		}
		
		// Set histogram counts, sum, and buckets
		dp.SetCount(uint64(len(durations)))
		
		sum := 0.0
		for _, d := range durations {
			sum += d
		}
		dp.SetSum(sum)
		
		// Set explicit bucket counts (using default buckets for now)
		buckets := []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0}
		explicitBounds := dp.ExplicitBounds()
		explicitBounds.FromRaw(buckets)
		
		bucketCounts := make([]uint64, len(buckets)+1)
		for _, duration := range durations {
			for i, bound := range buckets {
				if duration <= bound {
					bucketCounts[i]++
					break
				}
			}
			if duration > buckets[len(buckets)-1] {
				bucketCounts[len(buckets)]++
			}
		}
		bucketCountsSlice := dp.BucketCounts()
		bucketCountsSlice.FromRaw(bucketCounts)
	}
}

func (mr *metricsOTELReceiver) generateHTTPSizeHistograms(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Similar implementation for request/response size histograms
	// This is a simplified version - full implementation would follow similar pattern
}

func (mr *metricsOTELReceiver) generateGRPCMetrics(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Implementation for GRPC metrics
	// Similar pattern to HTTP metrics
}

func (mr *metricsOTELReceiver) generateDBMetrics(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Implementation for DB metrics
	// Similar pattern to HTTP metrics
}

func (mr *metricsOTELReceiver) generateMessagingMetrics(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Implementation for messaging metrics
	// Similar pattern to HTTP metrics
}

func (mr *metricsOTELReceiver) generateGPUMetrics(scopeMetrics pmetric.ScopeMetrics, spans []request.Span) {
	// Implementation for GPU metrics
	// Similar pattern to HTTP metrics
}

func (mr *metricsOTELReceiver) getHTTPAttributes(span *request.Span) []attribute.KeyValue {
	// Use the existing attribute getter logic
	attrs := make([]attribute.KeyValue, 0, len(mr.attrHTTPDuration))
	for _, getter := range mr.attrHTTPDuration {
		attrs = append(attrs, getter.Get(span))
	}
	return attrs
}

func (mr *metricsOTELReceiver) attributesToKey(attrs []attribute.KeyValue) string {
	// Convert attributes to a string key for grouping
	// This is a simplified implementation
	var key strings.Builder
	for _, attr := range attrs {
		key.WriteString(string(attr.Key))
		key.WriteString(":")
		key.WriteString(attr.Value.AsString())
		key.WriteString(";")
	}
	return key.String()
}

// getMetricsExporter creates a metrics exporter using the collector SDK
func getMetricsExporter(ctx context.Context, cfg *MetricsConfig) (exporter.Metrics, error) {
	switch proto := cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		slog.Debug("instantiating HTTP MetricsReceiver", "protocol", proto)
		opts, err := getHTTPMetricEndpointOptions(cfg)
		if err != nil {
			return nil, err
		}
		
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		
		set := getMetricsSettings(factory.Type())
		return factory.CreateMetrics(ctx, set, config)
		
	case ProtocolGRPC:
		slog.Debug("instantiating GRPC MetricsReceiver", "protocol", proto)
		opts, err := getGRPCMetricEndpointOptions(cfg)
		if err != nil {
			return nil, err
		}
		
		endpoint, _, err := parseMetricsEndpoint(cfg)
		if err != nil {
			return nil, err
		}
		
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		config.ClientConfig = configgrpc.ClientConfig{
			Endpoint: endpoint.String(),
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		
		set := getMetricsSettings(factory.Type())
		return factory.CreateMetrics(ctx, set, config)
		
	default:
		return nil, fmt.Errorf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf)
	}
}

// getMetricsSettings creates component settings for metrics exporter
func getMetricsSettings(componentType component.Type) exporter.Settings {
	logger, _ := zap.NewDevelopment()
	return exporter.Settings{
		ID:                component.NewID(componentType),
		TelemetrySettings: component.TelemetrySettings{Logger: logger},
		BuildInfo:         component.NewDefaultBuildInfo(),
	}
}
