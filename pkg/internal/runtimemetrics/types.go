// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package runtimemetrics reads runtime semantic convention metrics from
// instrumented processes. The initial reader supports Go processes.
package runtimemetrics // import "go.opentelemetry.io/obi/pkg/internal/runtimemetrics"

import (
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type Snapshot struct {
	Service svc.Attrs
	PID     app.PID
	Time    time.Time

	MemoryLimit       *int64
	MemoryAllocated   uint64
	MemoryAllocations uint64
	MemoryUsedStack   uint64
	MemoryUsedOther   uint64
	MemoryGCGoal      uint64
	GCCyclesAutomatic uint64
	GCCyclesForced    uint64
	GoroutineCount    int64
	ProcessorLimit    int64
	GOGC              *int64
}
