// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/agentctl"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestNodeDynamicReturnPatchLifecycleAndCallerReachability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	ensureInspectorPortAvailable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	fixture, err := filepath.Abs("spanbridge_test/patch_fixture.cjs")
	require.NoError(t, err)
	script := `
const fixture = require(process.argv[1]);
const fs = require('fs');
const original = fs.existsSync;
fs.existsSync = path => {
  if (typeof path === 'string' && path.startsWith('/dev/null/obi-dy/r')) {
    console.log(path.slice(18));
    return false;
  }
  return original(path);
};
globalThis.__t16Choke = fixture.choke;
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  input += chunk;
  let end;
  while ((end = input.indexOf('\n')) >= 0) {
    const [id, operation, value] = input.slice(0, end).trim().split(' ');
    input = input.slice(end + 1);
    if (operation === 'block-call') {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(value));
    }
    const result = fixture[operation === 'block-call' ? 'dynamicCaller' : operation](
      operation === 'block-call' ? 'after-ttl' : value);
    console.log('T16 ' + JSON.stringify({id, result, calls: fixture.callCount()}));
  }
});
setInterval(() => {}, 1000);
`
	cmd := exec.CommandContext(ctx, node, "--inspect=127.0.0.1:9229", "-e", script, fixture)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	pid := cmd.Process.Pid
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.DynamicInstrumentation.Enabled = true
	injector := NewNodeInjector(&cfg)
	var injected bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !injected {
		injected, err = injector.injectViaOpenInspector(pid)
		require.NoError(t, err)
		if !injected {
			time.Sleep(50 * time.Millisecond)
		}
	}
	require.True(t, injected, "the direct inspector injector did not attach; port 9229 may be busy")
	require.True(t, scanner.Scan())
	announcement := scanner.Text()
	require.Len(t, announcement, 64)

	processID := app.PID(pid)
	events := ebpfcommon.NewEBPFEventContext()
	registry := NewDynamicRegistry(ctx, config.DefaultDynamicInstrumentationConfig(), events)
	target := registry.Target(processID, nil)
	raw := make([]byte, 40)
	raw[0] = nodeDynamicReadyEvent
	binary.LittleEndian.PutUint32(raw[4:], uint32(processID))
	port, err := strconv.ParseUint(announcement[:16], 16, 32)
	require.NoError(t, err)
	binary.LittleEndian.PutUint32(raw[8:], uint32(port))
	token, err := hex.DecodeString(announcement[16:48])
	require.NoError(t, err)
	copy(raw[16:], token)
	revision, err := strconv.ParseUint(announcement[48:], 16, 64)
	require.NoError(t, err)
	binary.LittleEndian.PutUint64(raw[32:], revision)
	_, err = events.HandleInternalEvent(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)

	symbols, err := target.ResolveLiveSymbols(processID, "*patch_fixture.cjs:exports.choke")
	require.NoError(t, err)
	require.Len(t, symbols, 1)
	symbol := symbols[0]
	location, err := openLocationHook(pid)
	require.NoError(t, err)
	defer location.close()
	require.NoError(t, location.setFunctionBreakpoint())

	baseline, hits, returnError := nodeCallAtLocation(t, stdin, scanner, location, "baseline", "dynamicCaller", "before")
	require.Equal(t, "canary:before", baseline.Result)
	require.EqualValues(t, 1, baseline.Calls)
	require.EqualValues(t, 1, hits)
	require.Contains(t, returnError, "non-return position")
	_, err = target.command(ctx, agentctl.Attach, symbol, 80)
	require.NoError(t, err)
	spanConflict := agentctl.Patch{Method: symbol, Value: "NOT_APPLIED", ExpiresAt: time.Now().Add(5 * time.Second)}
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, spanConflict, 81)
	require.ErrorContains(t, err, "function already has a span probe")
	_, err = target.command(ctx, agentctl.Detach, "", 80)
	require.NoError(t, err)
	var evidence agentctl.PatchEvidence
	_, err = agentctl.ExchangeCounters(ctx, processID, uint32(port), tokenArray(token), target.session)
	require.ErrorContains(t, err, "PatchRefusal UNSUPPORTED_OPERATION")
	fragmented := agentctl.Patch{Method: symbol, Value: "T16_FRAGMENTED", ExpiresAt: time.Now().Add(5 * time.Second)}
	evidence, err = exchangePatchFragmented(ctx, processID, uint32(port), tokenArray(token), target.session, fragmented, 70)
	require.NoError(t, err)
	require.Empty(t, evidence)
	requireOversizedPatchRejected(t, processID, uint32(port), tokenArray(token), target.session)
	fragmentedResult := nodeCall(t, stdin, scanner, "fragmented", "dynamicCaller", "ignored")
	require.Equal(t, "T16_FRAGMENTED", fragmentedResult.Result)
	_, err = target.command(ctx, agentctl.Detach, "", 70)
	require.NoError(t, err)

	patch := agentctl.Patch{Method: symbol, Value: "T16_RETURN", ExpiresAt: time.Now().Add(500 * time.Millisecond)}
	strict := patch
	strict.RequireIdentity = true
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, strict, 69)
	require.ErrorContains(t, err, "PatchRefusal UNSUPPORTED_IDENTITY")
	identified := patch
	identified.Loader = "loader-1"
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, identified, 66)
	require.ErrorContains(t, err, "PatchRefusal UNSUPPORTED_IDENTITY")
	observe := patch
	observe.Observe = true
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, observe, 68)
	require.ErrorContains(t, err, "PatchRefusal UNSUPPORTED_MODE")
	predicate := patch
	predicate.Predicate = &agentctl.Predicate{Argument: 0, Contains: "blocked"}
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, predicate, 67)
	require.ErrorContains(t, err, "PatchRefusal UNSUPPORTED_PREDICATE")
	evidence, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, patch, 71)
	require.NoError(t, err)
	require.Empty(t, evidence.Loader)
	require.Empty(t, evidence.ArtifactSHA256)
	require.Empty(t, evidence.Fingerprint)
	patched := nodeCall(t, stdin, scanner, "patched", "dynamicCaller", "ignored")
	require.Equal(t, "T16_RETURN", patched.Result)
	require.EqualValues(t, 1, patched.Calls, "the wrapper must not run the original body")
	require.EqualValues(t, 1, location.hits, "the location hook cannot reach a call intercepted by the export wrapper")

	replacement := agentctl.Patch{Method: symbol, Value: "T16_REPLACED", ExpiresAt: time.Now().Add(5 * time.Second)}
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, replacement, 72)
	require.NoError(t, err)
	otherSymbols, err := target.ResolveLiveSymbols(processID, "*patch_fixture.cjs:exports.otherChoke")
	require.NoError(t, err)
	require.Len(t, otherSymbols, 1)
	duplicateCookie := agentctl.Patch{Method: otherSymbols[0], Value: "NOT_APPLIED", ExpiresAt: time.Now().Add(5 * time.Second)}
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, duplicateCookie, 72)
	require.ErrorContains(t, err, "patch cookie is already active")
	_, err = target.command(ctx, agentctl.Attach, symbol, 82)
	require.ErrorContains(t, err, "function already has a return patch")
	_, err = target.command(ctx, agentctl.Attach, otherSymbols[0], 72)
	require.ErrorContains(t, err, "patch cookie is already active")
	other := nodeCall(t, stdin, scanner, "other", "otherChoke", "control")
	require.Equal(t, "other:control", other.Result)

	oldExpiry := nodeCall(t, stdin, scanner, "old-expiry", "block-call", "750")
	require.Equal(t, "T16_REPLACED", oldExpiry.Result, "an old patch expiry must not remove its replacement")
	require.EqualValues(t, 1, oldExpiry.Calls)
	_, err = target.command(ctx, agentctl.Detach, "", 71)
	require.NoError(t, err)
	staleDetach := nodeCall(t, stdin, scanner, "stale-detach", "dynamicCaller", "ignored")
	require.Equal(t, "T16_REPLACED", staleDetach.Result, "a stale cookie detach must not remove its replacement")
	require.EqualValues(t, 1, staleDetach.Calls)

	destructured, hits, returnError := nodeCallAtLocation(t, stdin, scanner, location, "destructured", "destructuredCaller", "cached")
	require.Equal(t, "canary:cached", destructured.Result)
	require.EqualValues(t, 2, hits)
	require.Contains(t, returnError, "non-return position")
	closure, hits, returnError := nodeCallAtLocation(t, stdin, scanner, location, "closure", "closureCaller", "closed")
	require.Equal(t, "canary:closed", closure.Result)
	require.EqualValues(t, 3, closure.Calls)
	require.EqualValues(t, 3, hits)
	require.Contains(t, returnError, "non-return position")

	_, err = target.command(ctx, agentctl.Detach, "", 72)
	require.NoError(t, err)
	unpatched, hits, returnError := nodeCallAtLocation(t, stdin, scanner, location, "unpatched", "dynamicCaller", "after-remove")
	require.Equal(t, "canary:after-remove", unpatched.Result)
	require.EqualValues(t, 4, unpatched.Calls)
	require.EqualValues(t, 4, hits)
	require.Contains(t, returnError, "non-return position")

	expiring := agentctl.Patch{Method: symbol, Value: "T16_EXPIRED", ExpiresAt: time.Now().Add(150 * time.Millisecond)}
	_, err = agentctl.ExchangePatch(ctx, processID, uint32(port), tokenArray(token), target.session, expiring, 72)
	require.NoError(t, err)
	beforeExpiry := nodeCall(t, stdin, scanner, "before-expiry", "dynamicCaller", "not-run")
	require.Equal(t, "T16_EXPIRED", beforeExpiry.Result)
	expired, hits, returnError := nodeCallAtLocation(t, stdin, scanner, location, "after-expiry", "block-call", "250")
	require.Equal(t, "canary:after-ttl", expired.Result)
	require.EqualValues(t, 5, expired.Calls)
	require.EqualValues(t, 5, hits)
	require.Contains(t, returnError, "non-return position")
}

func TestNodeLodashReturnPatchCanary(t *testing.T) {
	appDir := os.Getenv("FLEETOPS_T16_NODE_APP")
	vulnerableDeps := os.Getenv("FLEETOPS_T16_VULNERABLE_DEPS")
	fixedDeps := os.Getenv("FLEETOPS_T16_FIXED_DEPS")
	if appDir == "" || vulnerableDeps == "" || fixedDeps == "" {
		t.Skip("set FLEETOPS_T16_NODE_APP, FLEETOPS_T16_VULNERABLE_DEPS, and FLEETOPS_T16_FIXED_DEPS to run the local CVE canary")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	version, err := exec.Command(node, "--version").Output()
	require.NoError(t, err)
	t.Logf("Node runtime: %s", strings.TrimSpace(string(version)))
	ensureInspectorPortAvailable(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	serverFile := filepath.Join(appDir, "server.cjs")
	fixed, _ := startT16NodeApp(ctx, t, node, serverFile, fixedDeps, false)
	vulnerable, scanner := startT16NodeApp(ctx, t, node, serverFile, vulnerableDeps, true)

	fixedBaseline := postNodeJSON[canaryResponse](t, fixed.port, "/canary")
	require.Equal(t, "4.17.23", fixedBaseline.Version)
	require.False(t, fixedBaseline.Hit)
	require.True(t, fixedBaseline.MarkerPresent)
	require.Equal(t, false, fixedBaseline.Result)
	vulnerableBaseline := postNodeJSON[canaryResponse](t, vulnerable.port, "/canary")
	require.Equal(t, "4.17.21", vulnerableBaseline.Version)
	require.True(t, vulnerableBaseline.Hit)
	require.False(t, vulnerableBaseline.MarkerPresent)
	require.Equal(t, true, vulnerableBaseline.Result)
	benignBaseline := postNodeJSON[benignDeleteResponse](t, vulnerable.port, "/benign-delete")
	require.Equal(t, true, benignBaseline.Result)
	require.False(t, benignBaseline.PropertyRemains)
	t.Logf("baseline: vulnerable=%+v fixed=%+v benign=%+v", vulnerableBaseline, fixedBaseline, benignBaseline)

	pid := vulnerable.cmd.Process.Pid
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.DynamicInstrumentation.Enabled = true
	injector := NewNodeInjector(&cfg)
	var injected bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !injected {
		injected, err = injector.injectViaOpenInspector(pid)
		require.NoError(t, err)
		if !injected {
			time.Sleep(50 * time.Millisecond)
		}
	}
	require.True(t, injected, "the direct inspector injector did not attach; port 9229 may be busy")
	announcement := readNodeAnnouncement(t, scanner)
	target, port, token := targetFromAnnouncement(ctx, t, app.PID(pid), announcement)
	symbols, err := target.ResolveLiveSymbols(app.PID(pid), "*lodash.js:exports.unset")
	require.NoError(t, err)
	require.Len(t, symbols, 1)
	symbol := symbols[0]
	t.Logf("Node target symbol: %s", symbol)

	patch := agentctl.Patch{Method: symbol, Value: "T16_CANARY_BLOCKED", ExpiresAt: time.Now().Add(5 * time.Second)}
	_, err = agentctl.ExchangePatch(ctx, app.PID(pid), port, token, target.session, patch, 91)
	require.NoError(t, err)
	patched := postNodeJSON[canaryResponse](t, vulnerable.port, "/canary")
	require.False(t, patched.Hit)
	require.True(t, patched.MarkerPresent)
	require.Equal(t, "string", patched.ResultType)
	require.Equal(t, "T16_CANARY_BLOCKED", patched.Result)
	benignPatched := postNodeJSON[benignDeleteResponse](t, vulnerable.port, "/benign-delete")
	require.Equal(t, "string", benignPatched.ResultType)
	require.Equal(t, "T16_CANARY_BLOCKED", benignPatched.Result)
	require.True(t, benignPatched.PropertyRemains, "the blanket return patch intentionally breaks ordinary unset behavior")
	t.Logf("patched: canary=%+v benign=%+v", patched, benignPatched)

	_, err = target.command(ctx, agentctl.Detach, "", 91)
	require.NoError(t, err)
	removed := postNodeJSON[canaryResponse](t, vulnerable.port, "/canary")
	require.True(t, removed.Hit)
	require.False(t, removed.MarkerPresent)

	expiring := agentctl.Patch{Method: symbol, Value: "T16_CANARY_BLOCKED", ExpiresAt: time.Now().Add(250 * time.Millisecond)}
	_, err = agentctl.ExchangePatch(ctx, app.PID(pid), port, token, target.session, expiring, 92)
	require.NoError(t, err)
	require.False(t, postNodeJSON[canaryResponse](t, vulnerable.port, "/canary").Hit)
	time.Sleep(350 * time.Millisecond)
	afterTTL := postNodeJSON[canaryResponse](t, vulnerable.port, "/canary")
	require.True(t, afterTTL.Hit)
	t.Logf("after detach=%+v after TTL=%+v", removed, afterTTL)
}

// This is deliberately a closed, test-only LiveEdit experiment. It does not
// accept arbitrary source from the control socket: it pins one script hash,
// one unique function body, and restores only the exact generation it wrote.
func TestNodeLiveEditLodashBodyAndCapturedCallers(t *testing.T) {
	appDir := os.Getenv("FLEETOPS_T16_NODE_APP")
	vulnerableDeps := os.Getenv("FLEETOPS_T16_VULNERABLE_DEPS")
	fixedDeps := os.Getenv("FLEETOPS_T16_FIXED_DEPS")
	if appDir == "" || vulnerableDeps == "" || fixedDeps == "" {
		t.Skip("set T16 Node app/dependency paths to run the LiveEdit canary")
	}
	node, err := exec.LookPath("node")
	require.NoError(t, err)
	ensureInspectorPortAvailable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	serverFile := filepath.Join(appDir, "server.cjs")
	fixed, _ := startT16NodeApp(ctx, t, node, serverFile, fixedDeps, false)
	vulnerable, _ := startT16NodeApp(ctx, t, node, serverFile, vulnerableDeps, true)
	require.False(t, postNodeJSON[canaryResponse](t, fixed.port, "/canary").Hit)
	require.True(t, postNodeJSON[canaryResponse](t, vulnerable.port, "/canary").Hit)

	inspector, err := openLocationHookWithBuffer(vulnerable.cmd.Process.Pid, 2*1024*1024)
	require.NoError(t, err)
	defer inspector.close()
	_, protocolError, err := inspector.command("Runtime.enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	_, protocolError, err = inspector.command("Debugger.enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	result, protocolError, err := inspector.command("Runtime.evaluate", map[string]any{
		"expression": "process.mainModule.require(process.env.FLEETOPS_DEPS + '/node_modules/lodash').unset",
	})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	remote := result["result"].(map[string]any)
	objectID := remote["objectId"].(string)
	props, protocolError, err := inspector.command("Runtime.getProperties", map[string]any{"objectId": objectID, "ownProperties": true})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	internal := props["internalProperties"].([]any)
	var scriptID string
	for _, item := range internal {
		property := item.(map[string]any)
		if property["name"] == "[[FunctionLocation]]" {
			location := property["value"].(map[string]any)["value"].(map[string]any)
			scriptID = location["scriptId"].(string)
		}
	}
	require.NotEmpty(t, scriptID, "Inspector must resolve the target function's script identity")
	sourceResult, protocolError, err := inspector.command("Debugger.getScriptSource", map[string]any{"scriptId": scriptID})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	original := sourceResult["scriptSource"].(string)
	require.Equal(t, "4c04561befdf653aef017a42ac5addf68ea943cdfca6bdee5ce04e04e8139f54", fmt.Sprintf("%x", sha256.Sum256([]byte(original))), "refuse to edit an unexpected script generation")
	oldBody := "function unset(object, path) {\n      return object == null ? true : baseUnset(object, path);\n    }"
	newBody := "function unset(object, path) {\n      return true;\n    }"
	require.Equal(t, 1, strings.Count(original, oldBody), "target body must be unique")
	patchedSource := strings.Replace(original, oldBody, newBody, 1)
	identity := func() {
		t.Helper()
		got := postNodeJSON[struct {
			SameObject bool `json:"sameObject"`
		}](t, vulnerable.port, "/unset-reference-identity")
		require.True(t, got.SameObject, "LiveEdit must preserve the original function object and pre-captured references")
	}
	identity()
	apply := func(source string, dryRun bool) map[string]any {
		t.Helper()
		answer, protocolError, err := inspector.command("Debugger.setScriptSource", map[string]any{
			"scriptId": scriptID, "scriptSource": source, "dryRun": dryRun,
		})
		require.NoError(t, err)
		require.Nil(t, protocolError)
		return answer
	}
	dry := apply(patchedSource, true)
	t.Logf("LiveEdit dryRun response fields: %v", dry)
	require.Equal(t, "Ok", dry["status"])
	assertPatched := func() {
		t.Helper()
		identity()
		// Export lookups and references cached before replacement all execute
		// the edited body; unlike export replacement, this mutates function code.
		for _, route := range []string{"/canary", "/cached-canary", "/closure-canary"} {
			got := postNodeJSON[canaryResponse](t, vulnerable.port, route)
			require.False(t, got.Hit, route)
			require.True(t, got.MarkerPresent, route)
		}
	}
	assertRestored := func() {
		t.Helper()
		identity()
		for _, route := range []string{"/canary", "/cached-canary", "/closure-canary"} {
			got := postNodeJSON[canaryResponse](t, vulnerable.port, route)
			require.True(t, got.Hit, route+" must reach the original body after restore")
		}
	}
	restoreOwnGeneration := func() {
		t.Helper()
		current, protocolError, err := inspector.command("Debugger.getScriptSource", map[string]any{"scriptId": scriptID})
		require.NoError(t, err)
		require.Nil(t, protocolError)
		currentSource := current["scriptSource"].(string)
		require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(patchedSource))), fmt.Sprintf("%x", sha256.Sum256([]byte(currentSource))), "do not overwrite a newer script generation")
		restoreDry := apply(original, true)
		require.Equal(t, "Ok", restoreDry["status"])
		restored := apply(original, false)
		t.Logf("LiveEdit restore response fields: %v", restored)
		require.Equal(t, "Ok", restored["status"])
	}

	installed := apply(patchedSource, false)
	installedAt := time.Now()
	t.Logf("LiveEdit explicit-removal apply response fields: %v", installed)
	require.Equal(t, "Ok", installed["status"])
	assertPatched()
	benign := postNodeJSON[benignDeleteResponse](t, vulnerable.port, "/benign-delete")
	require.True(t, benign.PropertyRemains, "replacing unset's body also breaks ordinary deletion")
	require.False(t, postNodeJSON[canaryResponse](t, fixed.port, "/canary").Hit, "fixed control remains fixed")
	restoreOwnGeneration()
	t.Logf("explicit removal restored after %s", time.Since(installedAt))
	assertRestored()

	installed = apply(patchedSource, false)
	installedAt = time.Now() // monotonic TTL starts after successful apply.
	t.Logf("LiveEdit TTL-cycle apply response fields: %v", installed)
	require.Equal(t, "Ok", installed["status"])
	assertPatched()
	const ttl = 300 * time.Millisecond
	ttlDeadline := installedAt.Add(ttl)
	timer := time.NewTimer(time.Until(ttlDeadline))
	<-timer.C
	// LiveEdit has no per-call expiry guard: source stays changed until the
	// external controller sends a generation-guarded restore command.
	restoreDispatch := time.Now()
	restoreOwnGeneration()
	restoreComplete := time.Now()
	t.Logf("external TTL restore dispatch lateness=%s completion lateness=%s", restoreDispatch.Sub(ttlDeadline), restoreComplete.Sub(ttlDeadline))
	assertRestored()
}

func TestNodeLiveEditInspectorScopeLimits(t *testing.T) {
	node, err := exec.LookPath("node")
	require.NoError(t, err)
	ensureInspectorPortAvailable(t)
	tmp := t.TempDir()
	commonJS := filepath.Join(tmp, "scope.cjs")
	require.NoError(t, os.WriteFile(commonJS, []byte(`
globalThis.__t16TopLevel = 'top-before';
globalThis.__t16Sync = function syncTarget() { return 'sync-before'; };
globalThis.__t16Async = async function asyncTarget() {
  await new Promise(resolve => { globalThis.__t16ReleaseAsync = resolve; });
  return 'async-before';
};
globalThis.__t16Generator = function* generatorTarget() {
  yield 'first';
  yield 'generator-before';
};
globalThis.__t16OnStack = function onStackTarget() { return 'stack-before'; };
globalThis.__t16AsyncPromise = globalThis.__t16Async();
	setTimeout(() => globalThis.__t16OnStack(), 15000);
process.stdin.on('data', () => globalThis.__t16OnStack());
setInterval(() => {}, 1000);
`), 0o600))
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--inspect=127.0.0.1:9229", commonJS)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	var inspector *locationInspector
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inspector, err = openLocationHookWithBuffer(cmd.Process.Pid, 128*1024)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.NoError(t, err)
	defer inspector.close()
	_, protocolError, err := inspector.command("Runtime.enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	_, protocolError, err = inspector.command("Debugger.enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	contextReady := false
	contextDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(contextDeadline) {
		_, contextError, contextErr := inspector.command("Runtime.evaluate", map[string]any{"expression": "typeof globalThis"})
		require.NoError(t, contextErr)
		if contextError == nil {
			contextReady = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, contextReady, "Node Inspector execution context should become available")

	getFunctionScript := func(expression string) (string, string) {
		t.Helper()
		value, evalError, evalErr := inspector.command("Runtime.evaluate", map[string]any{"expression": expression})
		require.NoError(t, evalErr)
		require.Nil(t, evalError)
		objectID := value["result"].(map[string]any)["objectId"].(string)
		properties, propertyError, propertyErr := inspector.command("Runtime.getProperties", map[string]any{"objectId": objectID, "ownProperties": true})
		require.NoError(t, propertyErr)
		require.Nil(t, propertyError)
		for _, raw := range properties["internalProperties"].([]any) {
			entry := raw.(map[string]any)
			if entry["name"] == "[[FunctionLocation]]" {
				loc := entry["value"].(map[string]any)["value"].(map[string]any)
				return loc["scriptId"].(string), objectID
			}
		}
		t.Fatalf("missing FunctionLocation for %s", expression)
		return "", ""
	}
	getSource := func(scriptID string) string {
		t.Helper()
		value, sourceError, sourceErr := inspector.command("Debugger.getScriptSource", map[string]any{"scriptId": scriptID})
		require.NoError(t, sourceErr)
		require.Nil(t, sourceError)
		return value["scriptSource"].(string)
	}
	probe := func(label, scriptID, source, old, replacement string, apply bool, afterApply ...func()) (map[string]any, map[string]any) {
		t.Helper()
		require.Equal(t, 1, strings.Count(source, old), label+" exact test-source identity")
		next := strings.Replace(source, old, replacement, 1)
		response, protocolErr, commandErr := inspector.command("Debugger.setScriptSource", map[string]any{
			"scriptId": scriptID, "scriptSource": next, "dryRun": true,
		})
		require.NoError(t, commandErr)
		t.Logf("%s dryRun fields=%v protocolError=%v", label, response, protocolErr)
		if protocolErr != nil || response["status"] != "Ok" || !apply {
			return response, protocolErr
		}
		response, protocolErr, commandErr = inspector.command("Debugger.setScriptSource", map[string]any{
			"scriptId": scriptID, "scriptSource": next, "dryRun": false,
		})
		require.NoError(t, commandErr)
		t.Logf("%s apply fields=%v protocolError=%v", label, response, protocolErr)
		if protocolErr == nil && response["status"] == "Ok" {
			current := getSource(scriptID)
			require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(next))), fmt.Sprintf("%x", sha256.Sum256([]byte(current))))
			for _, check := range afterApply {
				check()
			}
			restored, restoreError, restoreErr := inspector.command("Debugger.setScriptSource", map[string]any{
				"scriptId": scriptID, "scriptSource": source, "dryRun": true,
			})
			require.NoError(t, restoreErr)
			require.Nil(t, restoreError)
			require.Equal(t, "Ok", restored["status"])
			restored, restoreError, restoreErr = inspector.command("Debugger.setScriptSource", map[string]any{
				"scriptId": scriptID, "scriptSource": source, "dryRun": false,
			})
			require.NoError(t, restoreErr)
			require.Nil(t, restoreError)
			require.Equal(t, "Ok", restored["status"])
		}
		return response, protocolErr
	}

	cjsScript, _ := getFunctionScript("globalThis.__t16Sync")
	_, _ = getFunctionScript("globalThis.__t16Async")
	_, _ = getFunctionScript("globalThis.__t16Generator")
	cjsSource := getSource(cjsScript)
	result, protocolErr := probe("idle CJS function body", cjsScript, cjsSource, "return 'sync-before';", "return 'sync-after';", true)
	require.Nil(t, protocolErr)
	require.Equal(t, "Ok", result["status"])
	result, protocolErr = probe("CJS top-level", cjsScript, cjsSource, "top-before", "top-after", true, func() {
		value, evalError, evalErr := inspector.command("Runtime.evaluate", map[string]any{"expression": "globalThis.__t16TopLevel"})
		require.NoError(t, evalErr)
		require.Nil(t, evalError)
		require.Equal(t, "top-before", value["result"].(map[string]any)["value"], "LiveEdit of completed CJS top-level source must not be described as rerunning its initializer")
	})
	require.Nil(t, protocolErr)
	require.Equal(t, "Ok", result["status"])
	asyncResult, asyncError := probe("suspended async function body", cjsScript, cjsSource, "return 'async-before';", "return 'async-after';", true)
	t.Logf("suspended async observation: fields=%v error=%v", asyncResult, asyncError)
	require.Nil(t, asyncError)
	require.Equal(t, "BlockedByActiveGenerator", asyncResult["status"])
	_, protocolError, err = inspector.command("Runtime.evaluate", map[string]any{
		"expression": "globalThis.__t16GeneratorIterator = globalThis.__t16Generator(); globalThis.__t16GeneratorIterator.next()",
	})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	generatorResult, generatorError := probe("suspended generator function body", cjsScript, cjsSource, "yield 'generator-before';", "yield 'generator-after';", true)
	t.Logf("suspended generator observation: fields=%v error=%v", generatorResult, generatorError)
	require.Nil(t, generatorError)
	require.Equal(t, "BlockedByActiveGenerator", generatorResult["status"])
	// Pause at function entry (an active on-stack frame) and probe dryRun only;
	// applying source to a live frame is intentionally not attempted.
	stackScript, stackObject := getFunctionScript("globalThis.__t16OnStack")
	stackSource := getSource(stackScript)
	_, protocolError, err = inspector.command("Debugger.setBreakpointOnFunctionCall", map[string]any{"objectId": stackObject})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	_, err = stdin.Write([]byte("fire\n"))
	require.NoError(t, err)
	require.NoError(t, inspector.paused())
	stackCommand, stackError := probe("active on-stack function (paused)", stackScript, stackSource, "return 'stack-before';", "return 'stack-after';", false)
	_, resumeError, resumeErr := inspector.command("Debugger.resume", nil)
	require.NoError(t, resumeErr)
	require.Nil(t, resumeError)
	t.Logf("active on-stack result fields=%v protocolError=%v", stackCommand, stackError)
	require.Nil(t, stackError)
	require.Equal(t, "BlockedByActiveFunction", stackCommand["status"])
}

func TestNodeLiveEditESMScope(t *testing.T) {
	node, err := exec.LookPath("node")
	require.NoError(t, err)
	ensureInspectorPortAvailable(t)
	path := filepath.Join(t.TempDir(), "scope.mjs")
	source := "globalThis.__t16ESMTop = 'esm-top-before';\nexport function esmTarget() { return 'esm-before'; }\nglobalThis.esmTarget = esmTarget;\nsetInterval(() => {}, 1000);\n"
	require.NoError(t, os.WriteFile(path, []byte(source), 0o600))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--inspect=127.0.0.1:9229", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	var inspector *locationInspector
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inspector, err = openLocationHookWithBuffer(cmd.Process.Pid, 128*1024)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.NoError(t, err)
	defer inspector.close()
	_, protocolError, err := inspector.command("Runtime.enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	_, protocolError, err = inspector.command("Debugger.enable", map[string]any{})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	var objectID, scriptID string
	for time.Now().Before(deadline) {
		result, evalError, evalErr := inspector.command("Runtime.evaluate", map[string]any{"expression": "globalThis.esmTarget"})
		if evalErr == nil && evalError == nil {
			objectID = result["result"].(map[string]any)["objectId"].(string)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotEmpty(t, objectID, "ESM export function should be visible in the Inspector context")
	properties, protocolError, err := inspector.command("Runtime.getProperties", map[string]any{"objectId": objectID, "ownProperties": true})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	for _, raw := range properties["internalProperties"].([]any) {
		entry := raw.(map[string]any)
		if entry["name"] == "[[FunctionLocation]]" {
			scriptID = entry["value"].(map[string]any)["value"].(map[string]any)["scriptId"].(string)
		}
	}
	require.NotEmpty(t, scriptID)
	originalResult, protocolError, err := inspector.command("Debugger.getScriptSource", map[string]any{"scriptId": scriptID})
	require.NoError(t, err)
	require.Nil(t, protocolError)
	original := originalResult["scriptSource"].(string)
	for label, tc := range map[string]struct {
		pair       [2]string
		wantDryRun string
		wantApply  bool
	}{
		"ESM function body": {pair: [2]string{"esm-before", "esm-after"}, wantDryRun: "Ok", wantApply: true},
		"ESM top-level":     {pair: [2]string{"esm-top-before", "esm-top-after"}, wantDryRun: "BlockedByTopLevelEsModuleChange"},
	} {
		require.Equal(t, 1, strings.Count(original, tc.pair[0]), label+" exact fixture source")
		changed := strings.Replace(original, tc.pair[0], tc.pair[1], 1)
		response, responseError, commandErr := inspector.command("Debugger.setScriptSource", map[string]any{
			"scriptId": scriptID, "scriptSource": changed, "dryRun": true,
		})
		require.NoError(t, commandErr)
		t.Logf("%s dryRun fields=%v protocolError=%v", label, response, responseError)
		require.Nil(t, responseError)
		require.Equal(t, tc.wantDryRun, response["status"])
		if !tc.wantApply {
			continue
		}
		response, responseError, commandErr = inspector.command("Debugger.setScriptSource", map[string]any{
			"scriptId": scriptID, "scriptSource": changed, "dryRun": false,
		})
		require.NoError(t, commandErr)
		require.Nil(t, responseError)
		t.Logf("%s apply fields=%v", label, response)
		require.Equal(t, "Ok", response["status"])
		current, currentError, currentErr := inspector.command("Debugger.getScriptSource", map[string]any{"scriptId": scriptID})
		require.NoError(t, currentErr)
		require.Nil(t, currentError)
		require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(changed))), fmt.Sprintf("%x", sha256.Sum256([]byte(current["scriptSource"].(string)))))
		restored, restoreError, restoreErr := inspector.command("Debugger.setScriptSource", map[string]any{"scriptId": scriptID, "scriptSource": original, "dryRun": true})
		require.NoError(t, restoreErr)
		require.Nil(t, restoreError)
		require.Equal(t, "Ok", restored["status"])
		restored, restoreError, restoreErr = inspector.command("Debugger.setScriptSource", map[string]any{"scriptId": scriptID, "scriptSource": original, "dryRun": false})
		require.NoError(t, restoreErr)
		require.Nil(t, restoreError)
		require.Equal(t, "Ok", restored["status"])
	}
}

type nodeApp struct {
	cmd  *exec.Cmd
	port int
}

type readyResponse struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Version string `json:"version"`
}

func startT16NodeApp(ctx context.Context, t *testing.T, node, serverFile, dependencies string, inspect bool) (nodeApp, *bufio.Scanner) {
	t.Helper()
	args := []string{}
	if inspect {
		args = append(args, "--inspect=127.0.0.1:9229")
	}
	args = append(args, serverFile)
	cmd := exec.CommandContext(ctx, node, args...)
	cmd.Env = append(os.Environ(), "FLEETOPS_DEPS="+dependencies, "FLEETOPS_HOST=127.0.0.1", "FLEETOPS_PORT=0")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	var readyLine string
	for scanner.Scan() {
		line := scanner.Text()
		if stripped, ok := strings.CutPrefix(line, "READY "); ok {
			readyLine = stripped
			break
		}
	}
	require.NoError(t, scanner.Err(), "Node app stdout closed: %s", stderr.String())
	require.NotEmpty(t, readyLine, "Node app did not become ready: %s", stderr.String())
	var ready readyResponse
	require.NoError(t, json.Unmarshal([]byte(readyLine), &ready))
	require.Equal(t, "127.0.0.1", ready.Host)
	require.Positive(t, ready.Port)
	return nodeApp{cmd: cmd, port: ready.Port}, scanner
}

type canaryResponse struct {
	Version       string `json:"version"`
	Hit           bool   `json:"hit"`
	MarkerPresent bool   `json:"markerPresent"`
	Result        any    `json:"result"`
	ResultType    string `json:"resultType"`
}

type benignDeleteResponse struct {
	Result          any    `json:"result"`
	ResultType      string `json:"resultType"`
	PropertyRemains bool   `json:"propertyRemains"`
}

func postNodeJSON[T any](t *testing.T, port int, endpoint string) T {
	t.Helper()
	response, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d%s", port, endpoint), "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	var value T
	require.NoError(t, json.Unmarshal(body, &value), string(body))
	return value
}

func ensureInspectorPortAvailable(t *testing.T) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", "127.0.0.1:9229", 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Skip("Node Inspector port 9229 is already in use; direct injector test not run")
	}
}

func readNodeAnnouncement(t *testing.T, scanner *bufio.Scanner) string {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if announcement, ok := strings.CutPrefix(line, "OBI_READY "); ok {
			return announcement
		}
	}
	require.NoError(t, scanner.Err())
	t.Fatal("Node agent did not announce its local control socket")
	return ""
}

func targetFromAnnouncement(ctx context.Context, t *testing.T, pid app.PID, announcement string) (*DynamicTarget, uint32, [16]byte) {
	t.Helper()
	require.Len(t, announcement, 64)
	portValue, err := strconv.ParseUint(announcement[:16], 16, 32)
	require.NoError(t, err)
	port := uint32(portValue)
	tokenBytes, err := hex.DecodeString(announcement[16:48])
	require.NoError(t, err)
	token := tokenArray(tokenBytes)
	revision, err := strconv.ParseUint(announcement[48:], 16, 64)
	require.NoError(t, err)
	events := ebpfcommon.NewEBPFEventContext()
	registry := NewDynamicRegistry(ctx, config.DefaultDynamicInstrumentationConfig(), events)
	target := registry.Target(pid, nil)
	raw := make([]byte, 40)
	raw[0] = nodeDynamicReadyEvent
	binary.LittleEndian.PutUint32(raw[4:], uint32(pid))
	binary.LittleEndian.PutUint32(raw[8:], port)
	copy(raw[16:], token[:])
	binary.LittleEndian.PutUint64(raw[32:], revision)
	_, err = events.HandleInternalEvent(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	return target, port, token
}

type nodeCallResult struct {
	Result any   `json:"result"`
	Calls  int64 `json:"calls"`
}

func nodeCall(t *testing.T, stdin interface{ Write([]byte) (int, error) }, scanner *bufio.Scanner, id, operation, value string) nodeCallResult {
	t.Helper()
	_, err := fmt.Fprintf(stdin, "%s %s %s\n", id, operation, value)
	require.NoError(t, err)
	return readNodeCall(t, scanner, id)
}

func readNodeCall(t *testing.T, scanner *bufio.Scanner, id string) nodeCallResult {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "T16 ") {
			continue
		}
		var response struct {
			ID string `json:"id"`
			nodeCallResult
		}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "T16 ")), &response))
		if response.ID == id {
			return response.nodeCallResult
		}
	}
	require.NoError(t, scanner.Err())
	t.Fatal("Node process closed stdout before replying")
	return nodeCallResult{}
}

func tokenArray(value []byte) (token [16]byte) {
	copy(token[:], value)
	return token
}

func exchangePatchFragmented(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, patch agentctl.Patch, cookie uint64) (agentctl.PatchEvidence, error) {
	var payload bytes.Buffer
	writeString := func(value string) {
		_ = binary.Write(&payload, binary.BigEndian, uint32(len(value)))
		payload.WriteString(value)
	}
	writeString("")
	writeString(patch.Method)
	writeString("")
	payload.WriteByte(1)
	writeString(patch.Value)
	_ = binary.Write(&payload, binary.BigEndian, patch.ExpiresAt.UnixMilli())
	_ = binary.Write(&payload, binary.BigEndian, cookie)
	payload.WriteByte(0)
	writeString("")
	writeString("")
	writeString("")
	payload.WriteByte(0)
	_ = binary.Write(&payload, binary.BigEndian, int32(-1))
	writeString("")
	request := append(append(append([]byte{}, token[:]...), session[:]...), agentctl.AttachPatch)
	request = append(request, payload.Bytes()...)
	var connection net.Conn
	err := netns.WithNetNS(int(pid), func() error {
		var err error
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		return err
	})
	if err != nil {
		return agentctl.PatchEvidence{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	predicatePrefix := 33 + 4 + (4 + len(patch.Method)) + 4 + 1 + (4 + len(patch.Value)) + 8 + 8 + 1 + 12 + 1 + 4
	for _, b := range request[:predicatePrefix] {
		if _, err := connection.Write([]byte{b}); err != nil {
			return agentctl.PatchEvidence{}, err
		}
	}
	_ = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var earlyResponse [1]byte
	_, err = connection.Read(earlyResponse[:])
	netErr, isNetError := errors.AsType[net.Error](err)
	if !isNetError || !netErr.Timeout() {
		return agentctl.PatchEvidence{}, fmt.Errorf("Node responded or closed the connection before the fragmented predicate length arrived: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	for _, b := range request[predicatePrefix:] {
		if _, err := connection.Write([]byte{b}); err != nil {
			return agentctl.PatchEvidence{}, err
		}
	}
	var status [1]byte
	if _, err := io.ReadFull(connection, status[:]); err != nil {
		return agentctl.PatchEvidence{}, err
	}
	if status[0] != 0 {
		message, err := agentctl.ReadString(connection)
		if err != nil {
			return agentctl.PatchEvidence{}, err
		}
		return agentctl.PatchEvidence{}, fmt.Errorf("%s", message)
	}
	var evidence agentctl.PatchEvidence
	for _, field := range []*string{&evidence.Loader, &evidence.ArtifactSHA256, &evidence.Fingerprint} {
		value, err := agentctl.ReadString(connection)
		if err != nil {
			return agentctl.PatchEvidence{}, err
		}
		*field = value
	}
	return evidence, nil
}

func requireOversizedPatchRejected(t *testing.T, pid app.PID, port uint32, token, session [16]byte) {
	t.Helper()
	var connection net.Conn
	err := netns.WithNetNS(int(pid), func() error {
		var err error
		connection, err = (&net.Dialer{}).Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		return err
	})
	require.NoError(t, err)
	defer connection.Close()
	header := append(append(append([]byte{}, token[:]...), session[:]...), agentctl.AttachPatch)
	_, err = connection.Write(header)
	require.NoError(t, err)
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], 65537)
	_, err = connection.Write(oversized[:])
	require.NoError(t, err)
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	var response [1]byte
	_, err = connection.Read(response[:])
	require.Error(t, err, "oversized field must be rejected without a response")
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "oversized field must not be left pending")
	}
}

type locationInspector struct {
	connection *websocket.Conn
	nextID     int
	hits       int64
}

func openLocationHook(pid int) (*locationInspector, error) {
	return openLocationHookWithBuffer(pid, 4096)
}

func openLocationHookWithBuffer(pid, writeBufferSize int) (*locationInspector, error) {
	var conn net.Conn
	err := netns.WithNetNS(pid, func() error {
		var err error
		conn, err = connect("127.0.0.1", 9229)
		return err
	})
	if err != nil {
		return nil, err
	}
	injector := NewNodeInjector(&obi.DefaultConfig)
	wsURL, err := injector.requestDebuggerURL(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	ws, _, err := upgradeConn(conn, wsURL, writeBufferSize)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &locationInspector{connection: ws, nextID: 1}, nil
}

func (i *locationInspector) close() {
	_ = i.connection.Close()
}

func (i *locationInspector) command(method string, params map[string]any) (map[string]any, map[string]any, error) {
	id := i.nextID
	i.nextID++
	request, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return nil, nil, err
	}
	if err := i.connection.WriteMessage(websocket.TextMessage, request); err != nil {
		return nil, nil, err
	}
	for {
		if err := i.connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return nil, nil, err
		}
		_, message, err := i.connection.ReadMessage()
		if err != nil {
			return nil, nil, err
		}
		var response struct {
			ID     int            `json:"id"`
			Result map[string]any `json:"result"`
			Error  map[string]any `json:"error"`
		}
		if err := json.Unmarshal(message, &response); err != nil {
			return nil, nil, err
		}
		if response.ID == id {
			return response.Result, response.Error, nil
		}
	}
}

func (i *locationInspector) setFunctionBreakpoint() error {
	if _, _, err := i.command("Runtime.enable", nil); err != nil {
		return err
	}
	if _, _, err := i.command("Debugger.enable", nil); err != nil {
		return err
	}
	result, protocolError, err := i.command("Runtime.evaluate", map[string]any{"expression": "globalThis.__t16Choke"})
	if err != nil {
		return err
	}
	if protocolError != nil {
		return fmt.Errorf("Runtime.evaluate: %v", protocolError)
	}
	remoteObject := result["result"].(map[string]any)
	objectID := remoteObject["objectId"].(string)
	_, protocolError, err = i.command("Debugger.setBreakpointOnFunctionCall", map[string]any{"objectId": objectID})
	if err != nil {
		return err
	}
	if protocolError != nil {
		return fmt.Errorf("Debugger.setBreakpointOnFunctionCall: %v", protocolError)
	}
	return nil
}

func (i *locationInspector) paused() error {
	if err := i.connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	for {
		_, message, err := i.connection.ReadMessage()
		if err != nil {
			return err
		}
		var event struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(message, &event); err != nil {
			return err
		}
		if event.Method == "Debugger.paused" {
			i.hits++
			return nil
		}
	}
}

func nodeCallAtLocation(t *testing.T, stdin interface{ Write([]byte) (int, error) }, scanner *bufio.Scanner, location *locationInspector, id, operation, value string) (nodeCallResult, int64, string) {
	t.Helper()
	_, err := fmt.Fprintf(stdin, "%s %s %s\n", id, operation, value)
	require.NoError(t, err)
	require.NoError(t, location.paused())
	result, protocolError, err := location.command("Debugger.setReturnValue", map[string]any{
		"newValue": map[string]any{"type": "string", "value": "T16_LOCATION"},
	})
	require.NoError(t, err)
	_ = result
	require.NotNil(t, protocolError, "function-entry breakpoint must not offer a return-value override")
	returnError, ok := protocolError["message"].(string)
	require.True(t, ok)
	_, resumeError, err := location.command("Debugger.resume", nil)
	require.NoError(t, err)
	require.Nil(t, resumeError)
	response := readNodeCall(t, scanner, id)
	return response, location.hits, returnError
}
