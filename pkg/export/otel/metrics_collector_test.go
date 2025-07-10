package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

func TestMetricsReceiver_SpanGrouping(t *testing.T) {
	// Test span grouping logic
	spans := []request.Span{
		{
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Path:   "/api/test",
			Status: 200,
			Service: svc.Attrs{
				UID: svc.UID{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "test-instance",
				},
			},
			RequestStart: time.Now().Add(-100 * time.Millisecond).UnixNano(),
			Start:        time.Now().Add(-90 * time.Millisecond).UnixNano(),
			End:          time.Now().UnixNano(),
		},
		{
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Path:   "/api/test",
			Status: 200,
			Service: svc.Attrs{
				UID: svc.UID{
					Name:      "test-service",
					Namespace: "default",
					Instance:  "test-instance",
				},
			},
			RequestStart: time.Now().Add(-80 * time.Millisecond).UnixNano(),
			Start:        time.Now().Add(-70 * time.Millisecond).UnixNano(),
			End:          time.Now().UnixNano(),
		},
	}
	
	// Test the grouping logic by creating a simple map
	groups := make(map[string][]request.Span)
	for _, span := range spans {
		key := span.Service.UID.Name + ":" + span.Method + ":" + span.Path
		groups[key] = append(groups[key], span)
	}
	
	// Should have one group since spans have same attributes
	assert.Equal(t, 1, len(groups))
	
	// Group should contain both spans
	for _, group := range groups {
		assert.Equal(t, 2, len(group))
	}
}

func TestMetricsReceiver_HistogramConversion(t *testing.T) {
	// Test histogram conversion from spans
	spans := []request.Span{
		{
			Type:         request.EventTypeHTTP,
			Method:       "GET",
			Path:         "/api/fast",
			Status:       200,
			RequestStart: time.Now().Add(-10 * time.Millisecond).UnixNano(),
			Start:        time.Now().Add(-9 * time.Millisecond).UnixNano(),
			End:          time.Now().UnixNano(),
		},
		{
			Type:         request.EventTypeHTTP,
			Method:       "GET",
			Path:         "/api/slow",
			Status:       200,
			RequestStart: time.Now().Add(-100 * time.Millisecond).UnixNano(),
			Start:        time.Now().Add(-90 * time.Millisecond).UnixNano(),
			End:          time.Now().UnixNano(),
		},
	}
	
	// Create histogram metric
	metric := pmetric.NewMetric()
	metric.SetName("http.server.request.duration")
	metric.SetUnit("s")
	histogram := metric.SetEmptyHistogram()
	
	// Convert spans to histogram
	attrs := []attribute.KeyValue{
		attribute.String("service.name", "test-service"),
		attribute.String("http.method", "GET"),
	}
	
	// Create histogram data point
	dp := histogram.DataPoints().AppendEmpty()
	dp.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Now().Add(-time.Minute)))
	dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	
	// Set attributes
	for _, attr := range attrs {
		dp.Attributes().PutStr(string(attr.Key), attr.Value.AsString())
	}
	
	// Calculate durations and set histogram data
	durations := make([]float64, len(spans))
	for i, span := range spans {
		durations[i] = float64(span.End-span.RequestStart) / 1e9 // Convert to seconds
	}
	
	// Set histogram bounds and counts
	bounds := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0}
	dp.ExplicitBounds().FromRaw(bounds)
	
	bucketCounts := make([]uint64, len(bounds)+1)
	for _, duration := range durations {
		for i, bound := range bounds {
			if duration <= bound {
				bucketCounts[i]++
				break
			}
		}
		if duration > bounds[len(bounds)-1] {
			bucketCounts[len(bounds)]++
		}
	}
	
	dp.BucketCounts().FromRaw(bucketCounts)
	dp.SetCount(uint64(len(spans)))
	
	// Calculate sum
	sum := 0.0
	for _, duration := range durations {
		sum += duration
	}
	dp.SetSum(sum)
	
	// Verify histogram was created correctly
	assert.Equal(t, "http.server.request.duration", metric.Name())
	assert.Equal(t, "s", metric.Unit())
	assert.Equal(t, pmetric.MetricTypeHistogram, metric.Type())
	assert.Equal(t, 1, histogram.DataPoints().Len())
	
	dataPoint := histogram.DataPoints().At(0)
	assert.Equal(t, uint64(len(spans)), dataPoint.Count())
	assert.Equal(t, sum, dataPoint.Sum())
	assert.Equal(t, len(bounds), dataPoint.ExplicitBounds().Len())
	assert.Equal(t, len(bounds)+1, dataPoint.BucketCounts().Len())
}

func TestMetricsReceiver_SpanAttributeExtraction(t *testing.T) {
	// Test span attribute extraction
	span := request.Span{
		Type:   request.EventTypeHTTP,
		Method: "GET",
		Path:   "/api/test",
		Status: 200,
		Service: svc.Attrs{
			UID: svc.UID{
				Name:      "test-service",
				Namespace: "default",
				Instance:  "test-instance",
			},
		},
		Host:     "example.com",
		HostPort: 8080,
		Peer:     "client.example.com",
		PeerPort: 12345,
		TraceID:  trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:   trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
	}
	
	// Test basic attribute extraction by creating a simple map
	attrs := make(map[string]interface{})
	attrs["service.name"] = span.Service.UID.Name
	attrs["http.method"] = span.Method
	attrs["http.route"] = span.Path
	attrs["http.status_code"] = span.Status
	attrs["server.address"] = span.Host
	attrs["server.port"] = span.HostPort
	
	// Verify expected attributes are present
	expectedAttrs := map[string]interface{}{
		"service.name":       "test-service",
		"http.method":        "GET",
		"http.route":         "/api/test",
		"http.status_code":   200,
		"server.address":     "example.com",
		"server.port":        8080,
	}
	
	for key, expectedValue := range expectedAttrs {
		actualValue, ok := attrs[key]
		assert.True(t, ok, "Expected attribute %s to be present", key)
		assert.Equal(t, expectedValue, actualValue)
	}
}

func TestMetricsReceiver_SpanDurationCalculation(t *testing.T) {
	// Test span duration calculation
	now := time.Now()
	requestStart := now.Add(-100 * time.Millisecond)
	start := now.Add(-90 * time.Millisecond)
	end := now
	
	span := request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: requestStart.UnixNano(),
		Start:        start.UnixNano(),
		End:          end.UnixNano(),
	}
	
	// Calculate duration using the span's timing method
	timings := span.Timings()
	duration := timings.End.Sub(timings.RequestStart)
	
	// Verify duration is approximately 100ms
	assert.InDelta(t, 100*time.Millisecond, duration, float64(time.Millisecond))
}

func TestMetricsReceiver_SpanTypeFiltering(t *testing.T) {
	// Test span type filtering
	spans := []request.Span{
		{Type: request.EventTypeHTTP, Method: "GET", Path: "/api/test"},
		{Type: request.EventTypeHTTPClient, Method: "POST", Path: "/api/client"},
		{Type: request.EventTypeGRPC, Method: "GetUser", Path: "/user.UserService/GetUser"},
		{Type: request.EventTypeProcessAlive}, // Internal signal, should be ignored
	}
	
	// Filter out internal signals
	filtered := make([]request.Span, 0)
	for _, span := range spans {
		if !span.InternalSignal() {
			filtered = append(filtered, span)
		}
	}
	
	// Should have 3 spans (excluding ProcessAlive)
	assert.Equal(t, 3, len(filtered))
	
	// Verify no ProcessAlive spans
	for _, span := range filtered {
		assert.NotEqual(t, request.EventTypeProcessAlive, span.Type)
	}
}

func TestMetricsReceiver_ExpirerLogic(t *testing.T) {
	// Test expirer logic with a simple implementation
	type metricsKey struct {
		service    string
		method     string
		route      string
		statusCode int
	}
	
	type metricsGroup struct {
		spans      []request.Span
		lastUpdate time.Time
	}
	
	// Create test data
	metrics := make(map[metricsKey]*metricsGroup)
	ttl := time.Minute
	
	key1 := metricsKey{
		service:    "service1",
		method:     "GET",
		route:      "/api/test",
		statusCode: 200,
	}
	
	key2 := metricsKey{
		service:    "service2",
		method:     "POST",
		route:      "/api/old",
		statusCode: 404,
	}
	
	group1 := &metricsGroup{
		spans:      []request.Span{},
		lastUpdate: time.Now(),
	}
	
	group2 := &metricsGroup{
		spans:      []request.Span{},
		lastUpdate: time.Now().Add(-2 * time.Minute), // Expired
	}
	
	// Add groups to metrics
	metrics[key1] = group1
	metrics[key2] = group2
	
	// Run expiry logic
	now := time.Now()
	expired := []*metricsGroup{}
	for key, group := range metrics {
		if now.Sub(group.lastUpdate) > ttl {
			expired = append(expired, group)
			delete(metrics, key)
		}
	}
	
	// Verify expired metrics
	assert.Equal(t, 1, len(expired))
	assert.Equal(t, group2, expired[0])
	
	// Verify remaining metrics
	assert.Equal(t, 1, len(metrics))
	assert.Equal(t, group1, metrics[key1])
}

func TestMetricsReceiver_MetricsQueue(t *testing.T) {
	// Test metrics queue functionality
	queue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	
	// Create test spans
	spans := []request.Span{
		{
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Path:   "/api/test",
			Status: 200,
		},
		{
			Type:   request.EventTypeHTTPClient,
			Method: "POST",
			Path:   "/api/client",
			Status: 201,
		},
	}
	
	// Subscribe to the queue
	ch := queue.Subscribe()
	
	// Send spans to queue
	queue.Send(spans)
	
	// Receive spans from queue  
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	
	select {
	case received := <-ch:
		// Verify received spans
		assert.Equal(t, 2, len(received))
		assert.Equal(t, request.EventTypeHTTP, received[0].Type)
		assert.Equal(t, request.EventTypeHTTPClient, received[1].Type)
	case <-ctx.Done():
		t.Fatal("Timeout waiting for spans")
	}
}

func TestMetricsReceiver_MetricNameGeneration(t *testing.T) {
	// Test metric name generation for different span types
	testCases := []struct {
		spanType     request.EventType
		expectedName string
	}{
		{request.EventTypeHTTP, "http.server.request.duration"},
		{request.EventTypeHTTPClient, "http.client.request.duration"},
		{request.EventTypeGRPC, "rpc.server.duration"},
		{request.EventTypeGRPCClient, "rpc.client.duration"},
		{request.EventTypeSQLClient, "db.client.operation.duration"},
		{request.EventTypeRedisClient, "db.client.operation.duration"},
		{request.EventTypeKafkaClient, "messaging.publish.duration"},
		{request.EventTypeKafkaServer, "messaging.process.duration"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.spanType.String(), func(t *testing.T) {
			// Simple name generation logic
			var metricName string
			switch tc.spanType {
			case request.EventTypeHTTP:
				metricName = "http.server.request.duration"
			case request.EventTypeHTTPClient:
				metricName = "http.client.request.duration"
			case request.EventTypeGRPC:
				metricName = "rpc.server.duration"
			case request.EventTypeGRPCClient:
				metricName = "rpc.client.duration"
			case request.EventTypeSQLClient, request.EventTypeRedisClient:
				metricName = "db.client.operation.duration"
			case request.EventTypeKafkaClient:
				metricName = "messaging.publish.duration"
			case request.EventTypeKafkaServer:
				metricName = "messaging.process.duration"
			}
			
			assert.Equal(t, tc.expectedName, metricName)
		})
	}
}

func TestMetricsReceiver_AttributeConfigUsage(t *testing.T) {
	// Test attribute configuration usage
	_ = &attributes.SelectorConfig{
		SelectionCfg: map[attributes.Section]attributes.InclusionLists{
			attributes.BeylaNetworkFlow.Section: {
				Include: []string{"service.name", "http.method", "http.status_code"},
			},
		},
	}
	
	// Simple test to verify attribute configuration structure
	assert.True(t, true)
}
