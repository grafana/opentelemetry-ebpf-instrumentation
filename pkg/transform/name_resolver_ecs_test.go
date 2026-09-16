// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type fakeECSResolver map[string]string

func (f fakeECSResolver) ServiceNameForIP(ip string) (string, bool) {
	name, ok := f[ip]
	return name, ok
}

func TestResolveNamesFromECS(t *testing.T) {
	resolver := NameResolver{
		ecs: fakeECSResolver{
			"10.0.0.1": "storefront",
			"10.0.0.2": "checkout",
		},
		sources: ResolverECS,
		logger:  nrlog(),
	}

	t.Run("client", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTPClient,
			Peer: "10.0.0.1",
			Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{
				Name: "generated-container-name",
			}},
		}
		span.Service.SetAutoName()

		resolver.resolveNames(&span)

		assert.Equal(t, "storefront", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})

	t.Run("server", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTP,
			Peer: "10.0.0.1",
			Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{
				Name: "generated-container-name",
			}},
		}
		span.Service.SetAutoName()

		resolver.resolveNames(&span)

		assert.Equal(t, "checkout", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})

	t.Run("explicit service name", func(t *testing.T) {
		span := request.Span{
			Type: request.EventTypeHTTPClient,
			Peer: "10.0.0.1",
			Host: "10.0.0.2",
			Service: svc.Attrs{UID: svc.UID{
				Name: "configured-name",
			}},
		}

		resolver.resolveNames(&span)

		assert.Equal(t, "configured-name", span.Service.UID.Name)
		assert.Equal(t, "storefront", span.PeerName)
		assert.Equal(t, "checkout", span.HostName)
	})
}
