// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"reflect"
	"testing"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestApplyEnvVariables(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		expectName string
		expectNS   string
		expectMeta map[attr.Name]string
	}{
		{
			name:       "OTEL_SERVICE_NAME present, but also name is in the OTEL_RESOURCE_ATTRIBUTES",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service", "OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc,label1=1,label2=2"},
			expectName: "my-service",
			expectMeta: map[attr.Name]string{"label1": "1", "label2": "2", "service.name": "otel-svc"},
		},
		{
			name:       "OTEL_SERVICE_NAME present",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service"},
			expectName: "my-service",
			expectNS:   "",
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc"},
			expectName: "otel-svc",
			expectMeta: map[attr.Name]string{"service.name": "otel-svc"},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name and service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc,service.namespace=ns1"},
			expectName: "otel-svc",
			expectNS:   "ns1",
			expectMeta: map[attr.Name]string{"service.name": "otel-svc", "service.namespace": "ns1"},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=otel-ns"},
			expectNS:   "otel-ns",
			expectMeta: map[attr.Name]string{"service.namespace": "otel-ns"},
		},
		{
			name:       "No relevant env vars",
			envVars:    map[string]string{"FOO": "BAR"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "Improper resource attributes, no key - value pairs",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace,otel-ns"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "Unresolved values in name and namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=${test-ns},service.name=$(otel-ns)"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name: "Pre-set metadata is preserved over env resource attributes",
			envVars: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES": "deployment.environment=prod,custom.attr=from-env",
			},
			expectMeta: map[attr.Name]string{
				"deployment.environment": "staging",
				"custom.attr":            "from-env",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := New(Init{})
			if tt.name == "Pre-set metadata is preserved over env resource attributes" {
				fi.SetMetadata(map[attr.Name]string{
					"deployment.environment": "staging",
				})
			}
			fi.ApplyEnvVariables(tt.envVars)
			snap := fi.ServiceAttrs()
			if got := snap.UID.Name; got != tt.expectName {
				t.Errorf("UID.Name = %q, want %q", got, tt.expectName)
			}
			if got := snap.UID.Namespace; got != tt.expectNS {
				t.Errorf("UID.Namespace = %q, want %q", got, tt.expectNS)
			}
			if !reflect.DeepEqual(snap.EnvVars, tt.envVars) {
				t.Errorf("EnvVars = %#v, want %#v", snap.EnvVars, tt.envVars)
			}
			if !reflect.DeepEqual(snap.Metadata, tt.expectMeta) {
				t.Errorf("Metadata = %#v, want %#v", snap.Metadata, tt.expectMeta)
			}
		})
	}
}

func TestFileInfoKeepsProcessStartTime(t *testing.T) {
	info := New(Init{StartTime: 42})
	if info.StartTime() != 42 {
		t.Fatalf("StartTime() = %d, want 42", info.StartTime())
	}
}

func TestApplySDKService(t *testing.T) {
	t.Run("replaces inferred identity without mutating prior snapshots", func(t *testing.T) {
		fi := New(Init{})
		fi.SetAutoServiceName("remotedice-binary")
		fi.SetAutoServiceNamespace("kubernetes-namespace")
		fi.SetMetadata(map[attr.Name]string{attr.ServiceName: "remotedice-binary"})
		before := fi.UnsafeServiceAttrs()
		if !fi.ApplySDKService("otel-remotedice", "manual") {
			t.Fatal("SDK resource did not update inferred metadata")
		}
		after := fi.ServiceAttrs()
		if after.UID.Name != "otel-remotedice" || after.UID.Namespace != "manual" || after.AutoName() || after.AutoNamespace() {
			t.Fatalf("unexpected SDK identity: %+v", after)
		}
		if before.Metadata[attr.ServiceName] != "remotedice-binary" || after.Metadata[attr.ServiceName] != "otel-remotedice" || after.Metadata[attr.ServiceNamespace] != "manual" {
			t.Fatal("service resource metadata was not replaced immutably")
		}
		if fi.ApplySDKService("another-provider", "another-namespace") {
			t.Fatal("a second SDK provider replaced the first observed identity")
		}
	})
	t.Run("preserves explicit configuration", func(t *testing.T) {
		fi := New(Init{})
		fi.SetExplicitServiceName("configured")
		uid := fi.ServiceAttrs().UID
		uid.Namespace = "configured-namespace"
		fi.SetUID(uid)
		if fi.ApplySDKService("otel-remotedice", "manual") {
			t.Fatal("SDK resource replaced explicit configuration")
		}
	})
	t.Run("ignores empty and SDK default identities", func(t *testing.T) {
		fi := New(Init{})
		fi.SetAutoServiceName("kubernetes-service")
		for _, name := range []string{"", "unknown_service:remotedice"} {
			if fi.ApplySDKService(name, "") {
				t.Fatalf("unexpected change for %q", name)
			}
		}
	})
}
