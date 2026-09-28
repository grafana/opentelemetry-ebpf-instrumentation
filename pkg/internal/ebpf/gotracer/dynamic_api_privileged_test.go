// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDynamicAPIConfigReload(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "requires BPF privileges")
	build := func(variable, source, name string) string {
		t.Helper()
		if binary := os.Getenv(variable); binary != "" {
			return binary
		}
		binary := filepath.Join(t.TempDir(), name)
		output, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput()
		require.NoError(t, err, string(output))
		return binary
	}
	fixture := exec.CommandContext(t.Context(), build("OBI_DYNAMIC_TEST_BINARY", "./testdata/dynamicspans", "fixture"))
	input, err := fixture.StdinPipe()
	require.NoError(t, err)
	output, err := fixture.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, fixture.Start())
	t.Cleanup(func() { _ = fixture.Process.Kill(); _ = fixture.Wait() })
	lines := collectClientLines(t, "API target", output)
	waitForClientLine(t, lines, "READY", 10*time.Second)

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	require.NoError(t, err)
	listenAddress := listener.Addr().String()
	_, port, err := net.SplitHostPort(listenAddress)
	require.NoError(t, err)
	address := net.JoinHostPort("127.0.0.1", port)
	require.NoError(t, listener.Close())
	configPath := filepath.Join(t.TempDir(), "obi.json")
	writeConfig := func(rules string) {
		t.Helper()
		data := fmt.Sprintf(`{"trace_printer":"json","discovery":{"poll_interval":"100ms"},"dynamic_instrumentation":{"enabled":true,"listen_address":%q,"watch_interval":"100ms","rules":%s}}`, listenAddress, rules)
		require.NoError(t, os.WriteFile(configPath+".new", []byte(data), 0o600))
		require.NoError(t, os.Rename(configPath+".new", configPath))
	}
	writeConfig("[]")
	agent := exec.CommandContext(t.Context(), build("OBI_DYNAMIC_AGENT_BINARY", "../../../../cmd/obi", "obi"), "-config", configPath)
	log, err := os.Create(filepath.Join(t.TempDir(), "obi.log"))
	require.NoError(t, err)
	agent.Stdout, agent.Stderr = log, log
	require.NoError(t, agent.Start())
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_ = agent.Wait()
		require.NoError(t, log.Close())
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
	client := &http.Client{Timeout: 30 * time.Second}
	call := func(method, path, body string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(t.Context(), method, "http://"+address+path, bytes.NewBufferString(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		return response.StatusCode, data, err
	}
	require.Eventually(t, func() bool {
		status, _, err := call(http.MethodGet, "/healthz", "")
		return err == nil && status == http.StatusNoContent
	}, 15*time.Second, 100*time.Millisecond)
	rule := fmt.Sprintf(`{"service":[{"target_pids":[%d]}],"spans":[{"name":"api.call","on":{"function_span":"main.{outer,inner}"}}]}`, fixture.Process.Pid)
	status, data, err := call(http.MethodPut, "/v1/dynamic-instrumentation/rules/api", rule)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, string(data))
	var response struct {
		Probes []struct {
			Function string `json:"function"`
			Status   string `json:"status"`
		} `json:"probes"`
	}
	require.NoError(t, json.Unmarshal(data, &response))
	require.Len(t, response.Probes, 2)
	for _, probe := range response.Probes {
		require.Equal(t, "attached", probe.Status)
	}
	_, err = io.WriteString(input, "CALL\n")
	require.NoError(t, err)
	waitForClientLine(t, lines, "RESULT=", 10*time.Second)
	waitForFunctions := func(want ...string) {
		t.Helper()
		require.Eventually(t, func() bool {
			_, data, err := call(http.MethodGet, "/v1/dynamic-instrumentation/probes", "")
			if err != nil {
				return false
			}
			response.Probes = nil
			if json.Unmarshal(data, &response) != nil || len(response.Probes) != len(want) {
				return false
			}
			for i, name := range want {
				if response.Probes[i].Function != name {
					return false
				}
			}
			return true
		}, 15*time.Second, 100*time.Millisecond)
	}
	status, data, err = call(http.MethodDelete, "/v1/dynamic-instrumentation/probes", fmt.Sprintf(`{"service":[{"target_pids":[%d]}],"function":"main.inner"}`, fixture.Process.Pid))
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, status, string(data))
	waitForFunctions("main.outer")
	status, _, err = call(http.MethodDelete, "/v1/dynamic-instrumentation/rules/api", "")
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, status)
	waitForFunctions()
	writeConfig(`[{"service":[{"exe_path":"*/fixture"}],"spans":[{"name":"file.call","on":{"function_span":"main.outer"}}]}]`)
	waitForFunctions("main.outer")
	writeConfig(`[{"service":[{"exe_path":"*/fixture"}],"spans":[{"name":"file.call","on":{"function_span":"main.outer"}},{"name":"file.inner","on":{"function_span":"main.inner"}}]}]`)
	waitForFunctions("main.inner", "main.outer")
	writeConfig("[]")
	waitForFunctions()
	status, _, err = call(http.MethodGet, "/healthz", "")
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, status)
}
