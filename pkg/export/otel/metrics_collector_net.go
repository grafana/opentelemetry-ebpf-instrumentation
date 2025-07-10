package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/buildinfo"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/expire"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

func nmclog() *slog.Logger {
	return slog.With("component", "otel.NetworkMetricsCollector")
}

// NetworkMetricsReceiver creates a terminal node that consumes network records and sends OpenTelemetry metrics using collector SDK
func NetworkMetricsReceiver(
	ctxInfo *global.ContextInfo,
	cfg *NetMetricsConfig,
	input *msg.Queue[[]*ebpf.Record],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}

		nr := makeNetworkMetricsReceiver(ctx, ctxInfo, cfg, input)
		return nr.provideLoop, nil
	}
}

type networkMetricsReceiver struct {
	ctx      context.Context
	cfg      *NetMetricsConfig
	ctxInfo  *global.ContextInfo
	input    <-chan []*ebpf.Record
	attrProv *attributes.AttrSelector
	clock    *expire.CachedClock

	// Metric aggregation maps with expiration
	flowBytesAggregator      *expire.ExpiryMap[string]
	interZoneBytesAggregator *expire.ExpiryMap[string]
}

func makeNetworkMetricsReceiver(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *NetMetricsConfig,
	input *msg.Queue[[]*ebpf.Record],
) *networkMetricsReceiver {
	if cfg.SelectorCfg.SelectionCfg == nil {
		cfg.SelectorCfg.SelectionCfg = make(attributes.Selection)
	}

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.SelectorCfg)
	if err != nil {
		slog.Error("error creating network metrics attribute selector", "error", err)
		return nil
	}

	clock := expire.NewCachedClock(timeNow)

	return &networkMetricsReceiver{
		ctx:                      ctx,
		cfg:                      cfg,
		ctxInfo:                  ctxInfo,
		input:                    input.Subscribe(),
		attrProv:                 attrProv,
		clock:                    clock,
		flowBytesAggregator:      expire.NewExpiryMap[string](clock.Time, cfg.Metrics.TTL),
		interZoneBytesAggregator: expire.NewExpiryMap[string](clock.Time, cfg.Metrics.TTL),
	}
}

func (nr *networkMetricsReceiver) provideLoop(ctx context.Context) {
	log := nmclog()
	log.Debug("starting network metrics receiver loop")

	exp, err := getNetworkMetricsExporter(ctx, nr.cfg)
	if err != nil {
		log.Error("error creating network metrics exporter", "error", err)
		return
	}

	defer func() {
		if err := exp.Shutdown(ctx); err != nil {
			log.Error("error shutting down network metrics exporter", "error", err)
		}
	}()

	if err := exp.Start(ctx, nil); err != nil {
		log.Error("error starting network metrics exporter", "error", err)
		return
	}

	for records := range nr.input {
		nr.clock.Update()
		nr.processRecords(ctx, exp, records)
	}
}

func (nr *networkMetricsReceiver) processRecords(ctx context.Context, exp exporter.Metrics, records []*ebpf.Record) {
	if len(records) == 0 {
		return
	}

	metrics := nr.generateNetworkMetrics(records)
	if metrics.MetricCount() > 0 {
		if err := exp.ConsumeMetrics(ctx, metrics); err != nil {
			nmclog().Error("error sending network metrics to consumer", "error", err)
		}
	}
}

func (nr *networkMetricsReceiver) generateNetworkMetrics(records []*ebpf.Record) pmetric.Metrics {
	metrics := pmetric.NewMetrics()

	// Create resource scope
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	resource := resourceMetrics.Resource()

	// Set network service resource attributes
	resource.Attributes().PutStr("service.name", "beyla-network-flows")
	resource.Attributes().PutStr("service.instance.id", uuid.New().String())
	resource.Attributes().PutStr("telemetry.sdk.language", "go")
	resource.Attributes().PutStr("telemetry.sdk.name", "beyla")
	resource.Attributes().PutStr("telemetry.sdk.version", buildinfo.Version)

	if nr.ctxInfo.HostID != "" {
		resource.Attributes().PutStr("host.id", nr.ctxInfo.HostID)
	}

	// Add extra resource attributes
	for _, attr := range nr.ctxInfo.ExtraResourceAttributes {
		resource.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
	}

	// Create instrumentation scope
	scopeMetrics := resourceMetrics.ScopeMetrics().AppendEmpty()
	scopeMetrics.Scope().SetName("beyla-network")

	// Generate flow bytes metrics if enabled
	if nr.cfg.GloballyEnabled || nr.cfg.Metrics.NetworkFlowBytesEnabled() {
		nr.generateFlowBytesMetrics(scopeMetrics, records)
	}

	// Generate inter-zone bytes metrics if enabled
	if nr.cfg.Metrics.NetworkInterzoneMetricsEnabled() {
		nr.generateInterZoneBytesMetrics(scopeMetrics, records)
	}

	return metrics
}

func (nr *networkMetricsReceiver) generateFlowBytesMetrics(scopeMetrics pmetric.ScopeMetrics, records []*ebpf.Record) {
	// Create sum metric for flow bytes
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName(attributes.BeylaNetworkFlow.OTEL)
	metric.SetUnit("bytes")
	metric.SetDescription("total bytes_sent value of network flows observed by probe since its launch")

	sum := metric.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	sum.SetIsMonotonic(true)

	// Group records by attributes
	recordGroups := make(map[string][]*ebpf.Record)
	for _, record := range records {
		attrs := nr.getNetworkFlowAttributes(record)
		key := nr.attributesToMapKey(attrs)
		recordGroups[key] = append(recordGroups[key], record)
	}

	// Create data points
	for key, groupRecords := range recordGroups {
		if len(groupRecords) == 0 {
			continue
		}

		dp := sum.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

		// Set attributes from the first record in group
		attrs := nr.getNetworkFlowAttributes(groupRecords[0])
		for _, attr := range attrs {
			dp.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
		}

		// Calculate total bytes
		totalBytes := int64(0)
		for _, record := range groupRecords {
			totalBytes += int64(record.Metrics.Bytes)
		}

		dp.SetIntValue(totalBytes)

		// Track in cache for expiration
		cacheKey := nr.attributesToKey(attrs)
		nr.flowBytesAggregator.GetOrCreate(cacheKey, func() string { return key })
	}
}

func (nr *networkMetricsReceiver) generateInterZoneBytesMetrics(scopeMetrics pmetric.ScopeMetrics, records []*ebpf.Record) {
	// Filter records for inter-zone traffic
	interZoneRecords := make([]*ebpf.Record, 0)
	for _, record := range records {
		if record.Attrs.SrcZone != record.Attrs.DstZone {
			interZoneRecords = append(interZoneRecords, record)
		}
	}

	if len(interZoneRecords) == 0 {
		return
	}

	// Create sum metric for inter-zone bytes
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName(attributes.BeylaNetworkInterZone.OTEL)
	metric.SetUnit("bytes")
	metric.SetDescription("total bytes_sent value between Cloud availability zones")

	sum := metric.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	sum.SetIsMonotonic(true)

	// Group records by attributes
	recordGroups := make(map[string][]*ebpf.Record)
	for _, record := range interZoneRecords {
		attrs := nr.getNetworkInterZoneAttributes(record)
		key := nr.attributesToMapKey(attrs)
		recordGroups[key] = append(recordGroups[key], record)
	}

	// Create data points
	for key, groupRecords := range recordGroups {
		if len(groupRecords) == 0 {
			continue
		}

		dp := sum.DataPoints().AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

		// Set attributes from the first record in group
		attrs := nr.getNetworkInterZoneAttributes(groupRecords[0])
		for _, attr := range attrs {
			dp.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
		}

		// Calculate total bytes
		totalBytes := int64(0)
		for _, record := range groupRecords {
			totalBytes += int64(record.Metrics.Bytes)
		}

		dp.SetIntValue(totalBytes)

		// Track in cache for expiration
		cacheKey := nr.attributesToKey(attrs)
		nr.interZoneBytesCache.GetOrCreate(cacheKey, func() string { return key })
	}
}

func (nr *networkMetricsReceiver) getNetworkFlowAttributes(record *ebpf.Record) []attribute.KeyValue {
	// Use the existing attribute getter logic
	attrs := attributes.OpenTelemetryGetters(
		ebpf.RecordGetters,
		nr.attrProv.For(attributes.BeylaNetworkFlow))

	result := make([]attribute.KeyValue, 0, len(attrs))
	for _, getter := range attrs {
		result = append(result, getter.Get(record))
	}
	return result
}

func (nr *networkMetricsReceiver) getNetworkInterZoneAttributes(record *ebpf.Record) []attribute.KeyValue {
	// Use the existing attribute getter logic for inter-zone
	attrs := attributes.OpenTelemetryGetters(
		ebpf.RecordGetters,
		nr.attrProv.For(attributes.BeylaNetworkInterZone))

	result := make([]attribute.KeyValue, 0, len(attrs))
	for _, getter := range attrs {
		result = append(result, getter.Get(record))
	}
	return result
}

func (nr *networkMetricsReceiver) attributesToKey(attrs []attribute.KeyValue) []string {
	// Convert attributes to a string slice for grouping
	key := make([]string, 0, len(attrs)*2)
	for _, attr := range attrs {
		key = append(key, string(attr.Key), attr.Value.AsString())
	}
	return key
}

func (nr *networkMetricsReceiver) attributesToMapKey(attrs []attribute.KeyValue) string {
	// Convert attributes to a string key for map grouping
	key := ""
	for _, attr := range attrs {
		key += string(attr.Key) + ":" + attr.Value.AsString() + ";"
	}
	return key
}

func getNetworkMetricsExporter(ctx context.Context, cfg *NetMetricsConfig) (exporter.Metrics, error) {
	switch proto := cfg.Metrics.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "":
		return createNetworkHTTPMetricsExporter(ctx, cfg)
	case ProtocolGRPC:
		return createNetworkGRPCMetricsExporter(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func createNetworkHTTPMetricsExporter(ctx context.Context, cfg *NetMetricsConfig) (exporter.Metrics, error) {
	slog.Debug("instantiating HTTP NetworkMetricsReceiver", "protocol", cfg.Metrics.GetProtocol())

	opts, err := getHTTPMetricEndpointOptions(cfg.Metrics)
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
			InsecureSkipVerify: cfg.Metrics.InsecureSkipVerify,
		},
		Headers: convertNetworkHeaders(opts.Headers),
	}

	set := getNetworkMetricsSettings(factory.Type())
	exporter, err := factory.CreateMetrics(ctx, set, config)
	if err != nil {
		return nil, fmt.Errorf("can't create OTLP HTTP network metrics exporter: %w", err)
	}

	return exporterhelper.NewMetrics(ctx, set, cfg,
		exporter.ConsumeMetrics,
		exporterhelper.WithStart(exporter.Start),
		exporterhelper.WithShutdown(exporter.Shutdown),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
	)
}

func createNetworkGRPCMetricsExporter(ctx context.Context, cfg *NetMetricsConfig) (exporter.Metrics, error) {
	slog.Debug("instantiating GRPC NetworkMetricsReceiver", "protocol", cfg.Metrics.GetProtocol())

	opts, err := getGRPCMetricEndpointOptions(cfg.Metrics)
	if err != nil {
		return nil, fmt.Errorf("can't get GRPC metrics endpoint options: %w", err)
	}

	endpoint, _, err := parseMetricsEndpoint(cfg.Metrics)
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
			InsecureSkipVerify: cfg.Metrics.InsecureSkipVerify,
		},
		Headers: convertNetworkHeaders(opts.Headers),
	}

	set := getNetworkMetricsSettings(factory.Type())
	exporter, err := factory.CreateMetrics(ctx, set, config)
	if err != nil {
		return nil, fmt.Errorf("can't create OTLP GRPC network metrics exporter: %w", err)
	}

	return exporterhelper.NewMetrics(ctx, set, cfg,
		exporter.ConsumeMetrics,
		exporterhelper.WithStart(exporter.Start),
		exporterhelper.WithShutdown(exporter.Shutdown),
		exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
	)
}

func getNetworkMetricsSettings(componentType component.Type) exporter.Settings {
	logger, _ := zap.NewDevelopment()
	return exporter.Settings{
		ID:                component.NewID(componentType),
		TelemetrySettings: component.TelemetrySettings{Logger: logger},
		BuildInfo:         component.NewDefaultBuildInfo(),
	}
}

func convertNetworkHeaders(headers map[string]string) map[string]configopaque.String {
	result := make(map[string]configopaque.String)
	for k, v := range headers {
		result[k] = configopaque.String(v)
	}
	return result
}
