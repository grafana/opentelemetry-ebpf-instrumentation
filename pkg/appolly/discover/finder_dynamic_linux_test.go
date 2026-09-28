// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestDynamicGoInstrumentationPreservesProtocolOwnership(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.DynamicInstrumentation.Enabled = true
	pids := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), imetrics.NoopReporter{})
	pid, ns := app.PID(os.Getpid()), uint32(42)
	file := exec.New(exec.Init{})
	pids.AllowPID(pid, ns, file, ebpfcommon.PIDTypeGo)
	tracers := newGoTracersGroup(pids, &cfg, imetrics.NoopReporter{})
	require.Len(t, tracers, 1)
	dynamic := tracers[0]
	dynamic.AllowPID(pid, ns, file)
	require.True(t, pids.ValidPID(pid, ns, ebpfcommon.PIDTypeGo))
	require.False(t, pids.ValidPID(pid, ns, ebpfcommon.PIDTypeKProbes), "dynamic spans must not enroll Go processes for socket instrumentation")

	require.Implements(t, (*interface {
		LiveSpanDescriptors(*config.CustomSpanSpec, uint64) []*ebpfcommon.USDTProbeDesc
		RegisterLiveSpan(*config.CustomSpanSpec, uint64, string, uint64)
		RemoveFailedLiveSpan(uint64)
	})(nil), dynamic)

	generic := newGenericTracersGroup(pids, &cfg, imetrics.NoopReporter{})
	require.Len(t, generic, 1)
	otherPID := app.PID(os.Getppid())
	generic[0].AllowPID(otherPID, ns, file)
	require.True(t, pids.ValidPID(otherPID, ns, ebpfcommon.PIDTypeKProbes))
	require.False(t, pids.ValidPID(pid, ns, ebpfcommon.PIDTypeKProbes))
	require.True(t, pids.ValidPID(pid, ns, ebpfcommon.PIDTypeGo))
	require.NotEmpty(t, generic[0].KProbes(), "non-Go instrumentation must retain its socket probes")
}
