// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func TestServicesForPod(t *testing.T) {
	store := NewStore(&fakeInformer{}, ResourceLabels{}, nil, imetrics.NoopReporter{})
	for _, service := range []*informer.ObjectMeta{
		{Kind: "Service", Namespace: "shop", Name: "checkout", ServiceSelector: map[string]string{"app": "checkout"}},
		{Kind: "Service", Namespace: "shop", Name: "headless", ServiceSelector: map[string]string{"app": "checkout", "tier": "backend"}},
		{Kind: "Service", Namespace: "other", Name: "checkout", ServiceSelector: map[string]string{"app": "checkout"}},
		{Kind: "Service", Namespace: "shop", Name: "external"},
	} {
		require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: service}))
	}
	require.ElementsMatch(t, []string{"checkout", "headless"}, store.ServicesForPod("shop", map[string]string{"app": "checkout", "tier": "backend"}))
	require.Equal(t, []string{"checkout"}, store.ServicesForPod("shop", map[string]string{"app": "checkout"}))
	require.Empty(t, store.ServicesForPod("shop", nil))
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_UPDATED, Resource: &informer.ObjectMeta{Kind: "Service", Namespace: "shop", Name: "checkout", ServiceSelector: map[string]string{"app": "payments"}}}))
	require.Empty(t, store.ServicesForPod("shop", map[string]string{"app": "checkout"}))
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_DELETED, Resource: &informer.ObjectMeta{Kind: "Service", Namespace: "shop", Name: "headless"}}))
	require.Empty(t, store.ServicesForPod("shop", map[string]string{"app": "checkout", "tier": "backend"}))
}
