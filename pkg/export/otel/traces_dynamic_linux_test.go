// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package otel

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
)

func TestTracesDynamicSpansFromAvoidedService(t *testing.T) {
	for _, export := range []struct {
		name string
		span request.Span
	}{
		{"http", request.Span{Type: request.EventTypeHTTPClient, Method: "POST", Path: "/v1/traces", Status: 200}},
		{"grpc", request.Span{Type: request.EventTypeGRPCClient, Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export"}},
	} {
		t.Run(export.name, func(t *testing.T) {
			pid := app.PID(os.Getpid())
			pidInfo := request.PidInfo{HostPID: pid, UserPID: pid, Namespace: 42}
			service := svc.Attrs{UID: svc.UID{Name: "otel-remotedice", Namespace: "manual"}}
			service.ExportModes.AllowTraces()
			info := exec.New(exec.Init{Pid: pid, Service: service})
			filter := ebpfcommon.NewPIDsFilter(&services.DiscoveryConfig{
				ExcludeOTelInstrumentedServices: true,
			}, slog.Default(), imetrics.NoopReporter{})
			filter.AllowPID(pid, pidInfo.Namespace, info, ebpfcommon.PIDTypeGo)

			traceID, spanID, parentID := idgen.RandomTraceID(), idgen.RandomSpanID(), idgen.RandomSpanID()
			spans := []request.Span{
				export.span,
				{Type: request.EventTypeHTTP, Method: "GET", Path: "/roll", Status: 200},
				{Type: request.EventTypeGRPCClient, Path: "/dice/roll"},
				{Type: request.EventTypeSQLClient, Method: "SELECT"},
				{Type: request.EventTypeManualSpan},
				{
					Type: request.EventTypeCustomSpan, Method: "dynamic.roll",
					TraceID: traceID, SpanID: spanID, ParentSpanID: parentID, TraceFlags: 1,
					CustomSpan: &request.CustomSpan{Name: "dynamic.roll", Attrs: map[string]string{"arg0": "6"}},
				},
			}
			for i := range spans {
				spans[i].Pid = pidInfo
				spans[i].RequestStart, spans[i].Start, spans[i].End = 100, 100, 200
			}
			filtered := filter.Filter(spans)
			require.Len(t, filtered, len(spans))
			require.True(t, info.ExportsOTelTraces(), "the OTLP export must trigger avoided-service detection")
			for _, span := range filtered {
				require.True(t, span.Service.ExportsOTelTraces())
			}

			receiver := makeTracesTestReceiver([]instrumentations.Instrumentation{instrumentations.InstrumentationALL})
			attrs, err := receiver.getConstantAttributes()
			require.NoError(t, err)
			var exported []ptrace.Traces
			exporter := TestExporter{collector: func(traces ptrace.Traces) { exported = append(exported, traces) }}
			receiver.processSpans(t.Context(), exporter, filtered, attrs, sdktrace.AlwaysSample())

			require.Len(t, exported, 1)
			require.Equal(t, 1, exported[0].SpanCount(), "only the dynamic probe span should be exported")
			resource := exported[0].ResourceSpans().At(0)
			assert.Equal(t, "otel-remotedice", resource.Resource().Attributes().AsRaw()["service.name"])
			assert.Equal(t, "manual", resource.Resource().Attributes().AsRaw()["service.namespace"])
			span := resource.ScopeSpans().At(0).Spans().At(0)
			assert.Equal(t, "dynamic.roll", span.Name())
			assert.Equal(t, ptrace.SpanKindInternal, span.Kind())
			assert.Equal(t, pcommon.TraceID(traceID), span.TraceID())
			assert.Equal(t, pcommon.SpanID(spanID), span.SpanID())
			assert.Equal(t, pcommon.SpanID(parentID), span.ParentSpanID())
			assert.Equal(t, "6", span.Attributes().AsRaw()["arg0"])
			assert.True(t, info.ExportsOTelTraces(), "custom spans must not clear duplicate suppression for the service")

			exported = nil
			request.SetIgnoreTraces(&filtered[len(filtered)-1])
			receiver.processSpans(t.Context(), exporter, filtered, attrs, sdktrace.AlwaysSample())
			assert.Empty(t, exported, "explicit trace exclusions still apply to dynamic spans")
		})
	}
}
