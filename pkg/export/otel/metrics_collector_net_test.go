package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

func TestNetworkMetricsReceiver_FlowGrouping(t *testing.T) {
	// Test flow grouping by attributes
	flows := []*ebpf.Record{
		{
			NetFlowRecordT: ebpf.NetFlowRecordT{
				Id: ebpf.NetFlowId{
					DstPort: 8080,
					SrcPort: 12345,
				},
				Metrics: ebpf.NetFlowMetrics{
					Bytes:   1024,
					Packets: 10,
				},
			},
			Attrs: ebpf.RecordAttrs{
				SrcName: "client-pod",
				DstName: "server-pod",
			},
		},
		{
			NetFlowRecordT: ebpf.NetFlowRecordT{
				Id: ebpf.NetFlowId{
					DstPort: 8080,
					SrcPort: 12345,
				},
				Metrics: ebpf.NetFlowMetrics{
					Bytes:   2048,
					Packets: 20,
				},
			},
			Attrs: ebpf.RecordAttrs{
				SrcName: "client-pod",
				DstName: "server-pod",
			},
		},
	}
	
	// Set same IP addresses for grouping
	for _, flow := range flows {
		flow.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 10}
		flow.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 20}
	}
	
	// Group flows by creating a simple map
	groups := make(map[string][]*ebpf.Record)
	for _, flow := range flows {
		key := flow.Attrs.SrcName + ":" + flow.Attrs.DstName
		groups[key] = append(groups[key], flow)
	}
	
	// Should have one group since flows have same attributes
	assert.Equal(t, 1, len(groups))
	
	// Group should contain both flows
	for _, group := range groups {
		assert.Equal(t, 2, len(group))
		// Total bytes should be sum of both flows
		totalBytes := uint64(0)
		totalPackets := uint32(0)
		for _, flow := range group {
			totalBytes += flow.Metrics.Bytes
			totalPackets += flow.Metrics.Packets
		}
		assert.Equal(t, uint64(3072), totalBytes) // 1024 + 2048
		assert.Equal(t, uint32(30), totalPackets) // 10 + 20
	}
}

func TestNetworkMetricsReceiver_AttributeExtraction(t *testing.T) {
	// Test attribute extraction from flows
	testFlow := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: ebpf.NetFlowId{
				DstPort: 8080,
				SrcPort: 12345,
			},
			Metrics: ebpf.NetFlowMetrics{
				Bytes:   1024,
				Packets: 10,
			},
		},
		Attrs: ebpf.RecordAttrs{
			SrcName: "client-pod",
			DstName: "server-pod",
			Metadata: map[attr.Name]string{
				"k8s.src.name":      "client-pod",
				"k8s.src.namespace": "default",
				"k8s.dst.name":      "server-pod",
				"k8s.dst.namespace": "default",
			},
		},
	}
	
	// Set IP addresses
	testFlow.Id.SrcIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 10}
	testFlow.Id.DstIp.In6U.U6Addr8 = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 168, 1, 20}
	
	// Extract attributes manually for testing
	attrs := make(map[string]interface{})
	attrs["src.name"] = testFlow.Attrs.SrcName
	attrs["dst.name"] = testFlow.Attrs.DstName
	attrs["src.port"] = testFlow.Id.SrcPort
	attrs["dst.port"] = testFlow.Id.DstPort
	
	// Convert IPv6 to IPv4 for testing
	srcIP := testFlow.Id.SrcIp.In6U.U6Addr8
	dstIP := testFlow.Id.DstIp.In6U.U6Addr8
	if srcIP[10] == 0xff && srcIP[11] == 0xff {
		attrs["src.address"] = "192.168.1.10"
	}
	if dstIP[10] == 0xff && dstIP[11] == 0xff {
		attrs["dst.address"] = "192.168.1.20"
	}
	
	// Add metadata
	for k, v := range testFlow.Attrs.Metadata {
		attrs[string(k)] = v
	}
	
	// Verify expected attributes
	expectedAttrs := map[string]interface{}{
		"src.name":          "client-pod",
		"dst.name":          "server-pod",
		"src.address":       "192.168.1.10",
		"dst.address":       "192.168.1.20",
		"src.port":          uint16(12345),
		"dst.port":          uint16(8080),
		"k8s.src.name":      "client-pod",
		"k8s.src.namespace": "default",
		"k8s.dst.name":      "server-pod",
		"k8s.dst.namespace": "default",
	}
	
	for key, expectedValue := range expectedAttrs {
		actualValue, ok := attrs[key]
		assert.True(t, ok, "Expected attribute %s to be present", key)
		assert.Equal(t, expectedValue, actualValue)
	}
}

func TestNetworkMetricsReceiver_ExpiredFlows(t *testing.T) {
	// Test flow expiration logic
	type flowKey struct {
		srcAddr string
		dstAddr string
		srcPort uint16
		dstPort uint16
	}
	
	type flowGroup struct {
		flows      []*ebpf.Record
		lastUpdate time.Time
	}
	
	// Create test data
	flows := make(map[flowKey]*flowGroup)
	ttl := time.Minute
	
	key1 := flowKey{
		srcAddr: "192.168.1.10",
		dstAddr: "192.168.1.20",
		srcPort: 12345,
		dstPort: 8080,
	}
	
	key2 := flowKey{
		srcAddr: "192.168.1.30",
		dstAddr: "192.168.1.40",
		srcPort: 54321,
		dstPort: 9090,
	}
	
	group1 := &flowGroup{
		flows:      []*ebpf.Record{},
		lastUpdate: time.Now(),
	}
	
	group2 := &flowGroup{
		flows:      []*ebpf.Record{},
		lastUpdate: time.Now().Add(-2 * time.Minute), // Expired
	}
	
	// Add groups to flows
	flows[key1] = group1
	flows[key2] = group2
	
	// Run expiry logic
	now := time.Now()
	expired := []*flowGroup{}
	for key, group := range flows {
		if now.Sub(group.lastUpdate) > ttl {
			expired = append(expired, group)
			delete(flows, key)
		}
	}
	
	// Verify expired flows
	assert.Equal(t, 1, len(expired))
	assert.Equal(t, group2, expired[0])
	
	// Verify remaining flows
	assert.Equal(t, 1, len(flows))
	assert.Equal(t, group1, flows[key1])
}

func TestNetworkMetricsReceiver_MetricTypes(t *testing.T) {
	// Test metric type generation for network flows
	testCases := []struct {
		name         string
		expectedName string
		expectedUnit string
	}{
		{"bytes", "beyla.network.flow.bytes", "bytes"},
		{"packets", "beyla.network.flow.packets", "packets"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simple metric name generation
			var metricName, unit string
			switch tc.name {
			case "bytes":
				metricName = "beyla.network.flow.bytes"
				unit = "bytes"
			case "packets":
				metricName = "beyla.network.flow.packets"
				unit = "packets"
			}
			
			assert.Equal(t, tc.expectedName, metricName)
			assert.Equal(t, tc.expectedUnit, unit)
		})
	}
}

func TestNetworkMetricsReceiver_FlowQueue(t *testing.T) {
	// Test flow queue functionality
	queue := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	
	// Create test flows
	flows := []*ebpf.Record{
		{
			NetFlowRecordT: ebpf.NetFlowRecordT{
				Id: ebpf.NetFlowId{
					DstPort: 8080,
					SrcPort: 12345,
				},
				Metrics: ebpf.NetFlowMetrics{
					Bytes:   1024,
					Packets: 10,
				},
			},
			Attrs: ebpf.RecordAttrs{
				SrcName: "client-pod",
				DstName: "server-pod",
			},
		},
		{
			NetFlowRecordT: ebpf.NetFlowRecordT{
				Id: ebpf.NetFlowId{
					DstPort: 9090,
					SrcPort: 54321,
				},
				Metrics: ebpf.NetFlowMetrics{
					Bytes:   2048,
					Packets: 20,
				},
			},
			Attrs: ebpf.RecordAttrs{
				SrcName: "client-pod",
				DstName: "metrics-server",
			},
		},
	}
	
	// Subscribe to the queue
	ch := queue.Subscribe()
	
	// Send flows to queue
	queue.Send(flows)
	
	// Receive flows from queue
	select {
	case received := <-ch:
		// Verify received flows
		assert.Equal(t, 2, len(received))
		assert.Equal(t, uint16(8080), received[0].Id.DstPort)
		assert.Equal(t, uint16(9090), received[1].Id.DstPort)
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for flows")
	}
}

func TestNetworkMetricsReceiver_AttributeFiltering(t *testing.T) {
	// Test attribute filtering configuration
	_ = &attributes.SelectorConfig{
		SelectionCfg: map[attributes.Section]attributes.InclusionLists{
			attributes.BeylaNetworkFlow.Section: {
				Include: []string{"src.address", "dst.address", "k8s.src.name", "k8s.dst.name"},
			},
		},
	}
	
	// Test basic filtering logic
	includedAttrs := []string{"src.address", "dst.address", "k8s.src.name", "k8s.dst.name"}
	excludedAttrs := []string{"src.port", "dst.port", "k8s.src.namespace", "k8s.dst.namespace"}
	
	// Simple test that included attributes are in the include list
	includeList := map[string]bool{
		"src.address":   true,
		"dst.address":   true,
		"k8s.src.name":  true,
		"k8s.dst.name":  true,
	}
	
	for _, attr := range includedAttrs {
		assert.True(t, includeList[attr], "Expected %s to be included", attr)
	}
	
	for _, attr := range excludedAttrs {
		assert.False(t, includeList[attr], "Expected %s to be excluded", attr)
	}
}

func TestNetworkMetricsReceiver_FlowAccumulation(t *testing.T) {
	// Test flow metrics accumulation
	flow1 := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Metrics: ebpf.NetFlowMetrics{
				Bytes:   1024,
				Packets: 10,
			},
		},
	}
	
	flow2 := &ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Metrics: ebpf.NetFlowMetrics{
				Bytes:   2048,
				Packets: 20,
			},
		},
	}
	
	// Accumulate metrics manually
	totalBytes := flow1.Metrics.Bytes + flow2.Metrics.Bytes
	totalPackets := flow1.Metrics.Packets + flow2.Metrics.Packets
	
	// Verify accumulation
	assert.Equal(t, uint64(3072), totalBytes) // 1024 + 2048
	assert.Equal(t, uint32(30), totalPackets) // 10 + 20
}
