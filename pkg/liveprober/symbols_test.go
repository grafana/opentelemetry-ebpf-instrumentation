// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

type symbolResolverFunc func(app.PID, string) ([]string, error)

func (f symbolResolverFunc) ResolveLiveSymbols(pid app.PID, pattern string) ([]string, error) {
	return f(pid, pattern)
}

func TestSymbolsHTTPBeforeAttachingProbes(t *testing.T) {
	m := New()
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	m.identity = func(int) (processIdentity, error) { return processIdentity{startTime: 42}, nil }
	var resolved []app.PID
	m.Configure(config.DefaultDynamicInstrumentationConfig(), symbolResolverFunc(func(pid app.PID, pattern string) ([]string, error) {
		require.Equal(t, "*", pattern)
		resolved = append(resolved, pid)
		// A listing must release the manager lock before reading binary symbols.
		require.Empty(t, m.ListFunctions(nil))
		return []string{"main.(*Handler).ServeHTTP", "main.echo"}, nil
	}), nil)
	for _, pid := range []int{456, 123} {
		m.ObserveProcess(pid, func(criteria services.GlobDefinitionCriteria) bool {
			for _, selector := range criteria {
				for _, selected := range selector.PIDs {
					if int(selected) == pid {
						return true
					}
				}
			}
			return false
		})
	}
	m.SetService(123, svc.Attrs{UID: svc.UID{Name: "testserver", Namespace: "demo"}})
	handler := m.Handler()
	for _, test := range []struct {
		service string
		pids    []int
	}{
		{service: `[{"target_pids":[123]}]`, pids: []int{123}},
		{service: `[{"target_pids":[456]},{"target_pids":[123]}]`, pids: []int{123, 456}},
		{service: `[{"target_pids":[789]}]`, pids: []int{}},
	} {
		t.Run(test.service, func(t *testing.T) {
			resolved = nil
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/symbols?service="+url.QueryEscape(test.service), nil))
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			var result struct {
				Processes []ProcessSymbols `json:"processes"`
			}
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
			require.NotNil(t, result.Processes)
			require.Len(t, result.Processes, len(test.pids))
			require.Len(t, resolved, len(test.pids))
			for i, process := range result.Processes {
				require.Equal(t, test.pids[i], process.PID)
				require.Equal(t, app.PID(process.PID), resolved[i])
				require.Equal(t, []string{"main.(*Handler).ServeHTTP", "main.echo"}, process.Symbols)
				require.Empty(t, process.Error)
				if process.PID == 123 {
					require.Equal(t, "testserver", process.ServiceName)
					require.Equal(t, "demo", process.ServiceNamespace)
				}
			}
			require.Empty(t, m.rules)
			require.Empty(t, m.targets)
			require.Empty(t, m.ListFunctions(nil))
		})
	}
}

func TestSymbolsHTTPRejectsInvalidCriteria(t *testing.T) {
	m := New()
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	for _, service := range []string{"", "[]", "null", "[{}]", "{", `[{"target_pid":[123]}]`, `[{"exe_path":"["}]`} {
		t.Run(service, func(t *testing.T) {
			response := httptest.NewRecorder()
			m.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/symbols?service="+url.QueryEscape(service), nil))
			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
		})
	}
}

func TestSymbolsHTTPKeepsSuccessfulProcessesOnFailure(t *testing.T) {
	m, tracer := dynamicManager(t)
	m.ObserveProcess(456, func(services.GlobDefinitionCriteria) bool { return true })
	m.Configure(config.DefaultDynamicInstrumentationConfig(), symbolResolverFunc(func(pid app.PID, _ string) ([]string, error) {
		require.Equal(t, app.PID(456), pid, "registered targets must reuse their tracer's resolver")
		return nil, errors.New("executable has no resolvable function symbols")
	}), nil)
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/dynamic-instrumentation/symbols?service="+url.QueryEscape(`[{"target_pids":[123,456]}]`), nil))
	require.Equal(t, http.StatusMultiStatus, response.Code, response.Body.String())
	var result struct {
		Processes []ProcessSymbols `json:"processes"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.Len(t, result.Processes, 2)
	require.Equal(t, []string{"main.one", "main.two"}, result.Processes[0].Symbols)
	require.Empty(t, result.Processes[0].Error)
	require.Empty(t, result.Processes[1].Symbols)
	require.Contains(t, result.Processes[1].Error, "no resolvable function symbols")
	require.Empty(t, tracer.links)
}

func TestSymbolsRejectsChangedProcess(t *testing.T) {
	for _, duringRead := range []bool{false, true} {
		t.Run(strconv.FormatBool(duringRead), func(t *testing.T) {
			m, tracer := dynamicManager(t)
			identity := processIdentity{startTime: 99}
			m.identity = func(int) (processIdentity, error) { return identity, nil }
			if duringRead {
				identity.startTime = 42
				delete(m.targets, 123)
				m.symbols = symbolResolverFunc(func(app.PID, string) ([]string, error) {
					identity.startTime++
					return []string{"wrong.process"}, nil
				})
			}
			results := m.ListSymbols(t.Context(), ruleFor(t, "main.one").Service)
			require.Len(t, results, 1)
			require.Empty(t, results[0].Symbols)
			require.Equal(t, ErrTargetGone.Error(), results[0].Error)
			require.Empty(t, tracer.links)
		})
	}
}

func TestSymbolsCanceledRequestSkipsResolution(t *testing.T) {
	m, _ := dynamicManager(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	results := m.ListSymbols(ctx, ruleFor(t, "main.one").Service)
	require.Len(t, results, 1)
	require.Empty(t, results[0].Symbols)
	require.Equal(t, context.Canceled.Error(), results[0].Error)
}
