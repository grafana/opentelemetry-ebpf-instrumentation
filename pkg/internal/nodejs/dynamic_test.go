// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestNodeDynamicControl(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	fixture, err := filepath.Abs("spanbridge_test/dynamic_fixture.cjs")
	require.NoError(t, err)
	agent, err := filepath.Abs("dynamic.js")
	require.NoError(t, err)
	script := `require(process.argv[1]);
const fs = require('fs'); const original = fs.existsSync;
fs.existsSync = path => {
 if (typeof path === 'string' && path.startsWith('/dev/null/obi-dy/r')) {
  console.log(path.slice(18)); return false;
 }
 return original(path);
};
require(process.argv[2]); setInterval(() => {}, 1000);`
	cmd := exec.CommandContext(ctx, node, "-e", script, fixture, agent)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan())
	announcement := scanner.Text()
	require.Len(t, announcement, 64)
	pid := app.PID(cmd.Process.Pid)
	cfg := config.DefaultDynamicInstrumentationConfig()
	events := ebpfcommon.NewEBPFEventContext()
	registry := NewDynamicRegistry(ctx, cfg, events)
	target := registry.Target(pid, nil)
	require.Same(t, target, registry.Target(pid, nil))
	_, err = target.ResolveLiveSymbols(pid, "*")
	require.ErrorContains(t, err, "not ready")
	raw := make([]byte, 40)
	raw[0] = nodeDynamicReadyEvent
	binary.LittleEndian.PutUint32(raw[4:], uint32(pid))
	port, err := strconv.ParseUint(announcement[:16], 16, 32)
	require.NoError(t, err)
	binary.LittleEndian.PutUint32(raw[8:], uint32(port))
	token, err := hex.DecodeString(announcement[16:48])
	require.NoError(t, err)
	copy(raw[16:], token)
	revision, err := strconv.ParseUint(announcement[48:], 16, 64)
	require.NoError(t, err)
	binary.LittleEndian.PutUint64(raw[32:], revision)
	handled, err := events.HandleInternalEvent(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	require.True(t, handled)
	require.True(t, target.LiveSymbolsChanged())
	require.False(t, target.LiveSymbolsChanged())
	symbols, err := target.ResolveLiveSymbols(pid, "*dynamic_fixture.cjs:exports.{inner,outer}")
	require.NoError(t, err)
	require.Len(t, symbols, 2)
	require.True(t, strings.HasSuffix(symbols[0], ":exports.inner"))
	_, err = target.command(ctx, agentctl.Attach, symbols[0], 99)
	require.NoError(t, err)
	_, err = target.command(ctx, agentctl.Detach, "", 99)
	require.NoError(t, err)
	_, err = target.command(ctx, agentctl.Attach, "missing", 100)
	require.ErrorContains(t, err, "No writable")
	registry.Remove(pid)
	_, cached := registry.symbols.Get(pid, target.start, revision)
	require.False(t, cached)
	require.NotSame(t, target, registry.Target(pid, nil))
}

func TestDynamicAgentInjection(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.DynamicInstrumentation.Enabled = true
	injector := NewNodeInjector(&cfg)
	require.True(t, injector.Enabled())
	require.Contains(t, injector.agentCode(), _dynamicCode)
	require.Contains(t, injector.agentCode(), tracesEnabledOn)
	require.Contains(t, injector.agentCode(), ctxHookEnabledOn)
	cfg.DynamicInstrumentation.Enabled = false
	require.NotContains(t, NewNodeInjector(&cfg).agentCode(), _dynamicCode)
}
