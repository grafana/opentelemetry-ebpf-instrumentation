// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPOffsetFormsAndStatus(t *testing.T) {
	m := testManager(t, &fakeTracer{})
	defer m.Close()
	handler := m.Handler()
	for _, body := range []string{
		`{"generation":1,"pid":123,"offset":"0x100","span_name":"marker"}`,
		`{"generation":2,"pid":123,"offset":512,"span_name":"marker"}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/v1/probes/A", strings.NewReader(body))
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("PUT status %d: %s", resp.Code, resp.Body.String())
		}
	}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/v1/probes", nil))
	var got struct {
		Probes map[string]ProbeState `json:"probes"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Probes["A"].Offset != 512 || got.Probes["A"].LinkID == "" {
		t.Fatalf("unexpected status: %+v", got.Probes["A"])
	}
}
