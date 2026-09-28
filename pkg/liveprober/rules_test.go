// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

type resolvingTracer struct{ fakeTracer }

func (*resolvingTracer) ResolveLiveSymbols(_ app.PID, pattern string) ([]string, error) {
	switch pattern {
	case "*", "main.*":
		return []string{"main.one", "main.two"}, nil
	case "missing":
		return nil, errors.New("symbol missing")
	default:
		return []string{pattern}, nil
	}
}

func ruleFor(t *testing.T, function string) config.DynamicInstrumentationRule {
	t.Helper()
	rule, err := RuleJSON([]byte(fmt.Sprintf(`{"service":[{"target_pids":[123]}],"spans":[{"name":"custom","on":{"function_span":%q}}]}`, function)))
	require.NoError(t, err)
	return rule
}

func dynamicManager(t *testing.T) (*Manager, *resolvingTracer) {
	t.Helper()
	m := New()
	tracer := &resolvingTracer{}
	m.identity = func(int) (processIdentity, error) { return processIdentity{startTime: 42}, nil }
	m.ObserveProcess(123, func(criteria services.GlobDefinitionCriteria) bool {
		return len(criteria) > 0 && len(criteria[0].PIDs) > 0 && criteria[0].PIDs[0] == 123
	})
	require.NoError(t, m.RegisterTarget(123, 1, tracer))
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return m, tracer
}

func TestRuleOwnershipGlobDeleteAndReapply(t *testing.T) {
	m, tracer := dynamicManager(t)
	rule := ruleFor(t, "main.*")
	results, err := m.ApplyRule("api", rule)
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, r := range results {
		require.Equal(t, "attached", r.Status)
	}
	require.NoError(t, m.SetConfigRules([]config.DynamicInstrumentationRule{rule}))
	require.Len(t, tracer.links, 2, "shared rules must reuse physical probes")
	require.NoError(t, m.DeleteRule("api"))
	require.Len(t, m.ListFunctions(nil), 2, "file rule still owns the probes")
	require.NoError(t, m.DeleteFunctions(rule.Service, "main.one"))
	require.Len(t, m.ListFunctions(nil), 1)
	require.NoError(t, m.SetConfigRules(nil))
	require.Empty(t, m.ListFunctions(nil))
	for _, link := range tracer.links {
		require.True(t, link.closed)
	}
	_, err = m.ApplyRule("api", rule)
	require.NoError(t, err)
	require.Len(t, m.ListFunctions(nil), 2)
}

func TestRulesReportFailureAndPIDReuse(t *testing.T) {
	m, tracer := dynamicManager(t)
	results, err := m.ApplyRule("bad", ruleFor(t, "missing"))
	require.NoError(t, err)
	require.Equal(t, "error", results[0].Status)
	require.Empty(t, tracer.links)
	_, err = m.ApplyRule("ok", ruleFor(t, "main.one"))
	require.NoError(t, err)
	m.identity = func(int) (processIdentity, error) { return processIdentity{startTime: 99}, nil }
	results, err = m.ApplyRule("new", ruleFor(t, "main.two"))
	require.NoError(t, err)
	require.Equal(t, "error", results[0].Status)
	require.NoError(t, m.RegisterTarget(123, 1, tracer))
	require.True(t, tracer.links[0].closed)
	m.UnregisterTarget(123)
	require.Empty(t, m.ListFunctions(nil))
}

func TestDynamicHTTPReportsAttachmentAndRejectsBroadDelete(t *testing.T) {
	m, _ := dynamicManager(t)
	server := m.Handler()
	request := httptest.NewRequest(http.MethodPost, "/v1/dynamic-instrumentation/probes", strings.NewReader(`{"service":[{"target_pids":[123]}],"spans":[{"name":"one","on":{"function_span":"main.one"}}]}`))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"status":"attached"`)
	request = httptest.NewRequest(http.MethodDelete, "/v1/dynamic-instrumentation/probes", strings.NewReader(`{"function":"*"}`))
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)
	require.Len(t, m.ListFunctions(nil), 1)
	request = httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/probes?service="+url.QueryEscape(`[{"target_pids":[456]}]`), nil)
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.JSONEq(t, `{"probes":[]}`, response.Body.String())
	for _, pid := range []int{456, 123} {
		request = httptest.NewRequest(http.MethodDelete, "/v1/dynamic-instrumentation/probes", strings.NewReader(fmt.Sprintf(`{"service":[{"target_pids":[%d]}],"function":"main.one"}`, pid)))
		response = httptest.NewRecorder()
		server.ServeHTTP(response, request)
		require.Equal(t, http.StatusNoContent, response.Code)
		if pid == 456 {
			require.Len(t, m.ListFunctions(nil), 1)
		}
	}
	require.Empty(t, m.ListFunctions(nil))
}

func TestWatchConfigAtomicReplaceAndInvalidFile(t *testing.T) {
	m, _ := dynamicManager(t)
	cfg := config.DefaultDynamicInstrumentationConfig()
	cfg.Enabled = true
	cfg.WatchInterval = 5 * time.Millisecond
	path := filepath.Join(t.TempDir(), "obi.yml")
	require.NoError(t, os.WriteFile(path, []byte("dynamic_instrumentation:\n  rules: []\n"), 0o600))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); m.watchConfig(ctx, cfg, path) }()
	replace := func(text string) {
		t.Helper()
		tmp := path + ".new"
		require.NoError(t, os.WriteFile(tmp, []byte(text), 0o600))
		require.NoError(t, os.Rename(tmp, path))
	}
	replace("dynamic_instrumentation:\n  rules:\n    - service: [{target_pids: [123]}]\n      spans: [{name: one, on: {function_span: main.one}}]\n")
	require.Eventually(t, func() bool { return len(m.ListFunctions(nil)) == 1 }, time.Second, 5*time.Millisecond)
	replace("dynamic_instrumentation: [invalid")
	time.Sleep(20 * time.Millisecond)
	require.Len(t, m.ListFunctions(nil), 1)
	_, err := m.ApplyRule("api", ruleFor(t, "main.two"))
	require.NoError(t, err)
	replace("dynamic_instrumentation:\n  rules: []\n")
	require.Eventually(t, func() bool { return len(m.ListFunctions(nil)) == 1 && m.ListFunctions(nil)[0].Function == "main.two" }, time.Second, 5*time.Millisecond)
	cancel()
	<-done
}

func TestReplacementFailurePreservesAttachedProbe(t *testing.T) {
	m, tracer := dynamicManager(t)
	rule := ruleFor(t, "main.one")
	_, err := m.ApplyRule("rule", rule)
	require.NoError(t, err)
	tracer.rejectAt = 2
	rule.Spans[0].Name = "replacement"
	results, err := m.ApplyRule("rule", rule)
	require.NoError(t, err)
	require.Equal(t, "error", results[0].Status)
	require.False(t, tracer.links[0].closed)
	require.Equal(t, "custom", m.ListFunctions(nil)[0].SpanName)
}

func TestConfigDecodeRejectsUnknownRules(t *testing.T) {
	_, err := dynamicRules([]byte("dynamic_instrumentation:\n  rulse: []\n"), config.DefaultDynamicInstrumentationConfig())
	require.Error(t, err)
}

func TestMetadataChangeReconcilesExistingProcess(t *testing.T) {
	m, tracer := dynamicManager(t)
	selected := false
	m.ObserveProcess(123, func(services.GlobDefinitionCriteria) bool { return selected })
	results, err := m.ApplyRule("service", ruleFor(t, "main.one"))
	require.NoError(t, err)
	require.Equal(t, "pending", results[0].Status)
	selected = true
	m.RefreshMatches()
	require.Len(t, m.ListFunctions(nil), 1)
	m.RefreshMatches()
	require.Len(t, tracer.links, 1)
	selected = false
	m.RefreshMatches()
	require.Empty(t, m.ListFunctions(nil))
	require.True(t, tracer.links[0].closed)
}

func TestRemoteAPIWithoutAuthentication(t *testing.T) {
	m, _ := dynamicManager(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/probes", nil)
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)

	cfg := config.DefaultDynamicInstrumentationConfig()
	for _, address := range []string{"0.0.0.0:8089", "[::]:8089", ":8089", "192.0.2.1:8089"} {
		cfg.ListenAddress = address
		require.NoError(t, cfg.Validate(), address)
	}
	cfg.ListenAddress = "0.0.0.0"
	require.ErrorContains(t, cfg.Validate(), "listen_address")
}

func TestDeletedFunctionStaysRemovedUntilExplicitlyRequested(t *testing.T) {
	m, _ := dynamicManager(t)
	first := ruleFor(t, "main.one")
	require.NoError(t, m.SetConfigRules([]config.DynamicInstrumentationRule{first}))
	require.NoError(t, m.DeleteFunctions(first.Service, "main.one"))
	_, err := m.ApplyRule("unrelated", ruleFor(t, "main.two"))
	require.NoError(t, err)
	require.Len(t, m.ListFunctions(nil), 1)
	require.Equal(t, "main.two", m.ListFunctions(nil)[0].Function)
	require.NoError(t, m.SetConfigRules([]config.DynamicInstrumentationRule{first}))
	require.Len(t, m.ListFunctions(nil), 2)
}

func TestShutdownCannotReattachRemainingRules(t *testing.T) {
	m, tracer := dynamicManager(t)
	_, err := m.ApplyRule("first", ruleFor(t, "main.one"))
	require.NoError(t, err)
	_, err = m.ApplyRule("second", ruleFor(t, "main.two"))
	require.NoError(t, err)
	require.NoError(t, m.Close())
	require.NoError(t, m.DeleteRule("first"))
	m.RefreshMatches()
	require.Len(t, tracer.links, 2)
	require.Empty(t, m.ListFunctions(nil))
	for _, link := range tracer.links {
		require.True(t, link.closed)
	}
}

func TestConfigRuleReportsSymbolFailure(t *testing.T) {
	m, _ := dynamicManager(t)
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	require.NoError(t, m.SetConfigRules([]config.DynamicInstrumentationRule{
		ruleFor(t, "main.one"),
		ruleFor(t, "missing"),
	}))
	require.Len(t, m.ListFunctions(nil), 1)
	require.Contains(t, logs.String(), "rule=config/1")
	require.Contains(t, logs.String(), "pid=123")
	require.Contains(t, logs.String(), "function=missing")
	require.Contains(t, logs.String(), "symbol missing")

	firstLog := logs.String()
	_, err := m.ApplyRule("api", ruleFor(t, "main.one"))
	require.NoError(t, err)
	require.Equal(t, firstLog, logs.String(), "unchanged failures must not repeat on reconciliation")
}
