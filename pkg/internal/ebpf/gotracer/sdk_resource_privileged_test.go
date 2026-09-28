// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestSDKResourceWithoutDynamicSpans(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "requires BPF privileges")
	require.NoError(t, rlimit.RemoveMemlock())
	binary := os.Getenv("OBI_DYNAMIC_TEST_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "sdk-resource")
		output, err := exec.Command("go", "build", "-o", binary, "testdata/dynamicspans/main.go").CombinedOutput()
		require.NoError(t, err, string(output))
	}
	for _, sampled := range []string{"sampled", "unsampled"} {
		t.Run(sampled, func(t *testing.T) {
			command := exec.CommandContext(t.Context(), binary)
			command.Env = os.Environ()
			if sampled == "unsampled" {
				command.Env = append(command.Env, "OBI_TEST_SDK_UNSAMPLED=1")
			}
			stdin, err := command.StdinPipe()
			require.NoError(t, err)
			stdout, err := command.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, command.Start())
			t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
			lines := collectClientLines(t, "SDK resource target", stdout)
			waitForClientLine(t, lines, "READY=", 10*time.Second)

			cfg := obi.DefaultConfig
			require.False(t, cfg.DynamicInstrumentation.IsEnabled())
			pids := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
			goTracer := New(pids, &cfg, imetrics.NoopReporter{})
			eventContext := ebpfcommon.NewEBPFEventContext()
			eventContext.CommonPIDsFilter = pids
			tracer := ebpftracer.NewProcessTracer(ebpftracer.Go, []ebpftracer.Tracer{goTracer}, &cfg, imetrics.NoopReporter{})
			require.NoError(t, tracer.Init(eventContext, &cfg))
			pid := app.PID(command.Process.Pid)
			info := goProcessFileInfo(t, pid)
			info.SetAutoServiceName("binary-fallback")
			info.SetAutoServiceNamespace("k8s-fallback")
			offsets, err := goexec.InspectOffsets(info, goFunctionNames(&cfg))
			require.NoError(t, err)
			ebpftracer.AddSDKContextOffsets(info.ELF(), offsets)
			tracer.AllowPID(pid, info.Ns(), info)
			executable, err := link.OpenExecutable(info.ProExeLinkPath())
			require.NoError(t, err)
			require.NoError(t, tracer.NewExecutable(executable, &ebpftracer.Instrumentable{Type: svc.InstrumentableGolang, FileInfo: info, Offsets: offsets}))
			spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(16))
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); tracer.Run(ctx, eventContext, spans) }()
			t.Cleanup(func() { cancel(); <-done; spans.Close() })

			_, err = io.WriteString(stdin, "CALL\n")
			require.NoError(t, err)
			waitForClientLine(t, lines, "RESULT=", 10*time.Second)
			require.Eventually(t, func() bool {
				service := info.ServiceAttrs()
				return service.UID.Name == "otel-remotedice" && service.UID.Namespace == "manual"
			}, 10*time.Second, 10*time.Millisecond)
		})
	}
}
