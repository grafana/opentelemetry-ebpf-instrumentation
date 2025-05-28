package appolly

import (
	"context"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/otel"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/connector"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/discover"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/pipe/global"
	"github.com/stretchr/testify/assert"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		context.Background(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&beyla.Config{
			ChannelBufferLen: 1,
			Traces: otel.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(context.Background(), events)

	for i := 0; i < 100; i++ {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: int32(i)}},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}
