// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func FindLibMaps(pid app.PID) ([]*procfs.ProcMap, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}

	return proc.ProcMaps()
}

func LibPath(name string, maps []*procfs.ProcMap) *procfs.ProcMap {
	for _, m := range maps {
		if strings.Contains(m.Pathname, string(filepath.Separator)+name) && m.Perms.Execute {
			return m
		}
	}

	return nil
}

// FindExeBaseAddr reads /proc/<pid>/maps to find the base virtual address
// where the main executable is mapped. This is needed for PIE binaries where
// ELF symbol addresses are relative to the load base.
func FindExeBaseAddr(pid app.PID) (uint64, error) {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		return 0, fmt.Errorf("readlink exe: %w", err)
	}

	maps, err := FindLibMaps(pid)
	if err != nil {
		return 0, fmt.Errorf("read proc maps: %w", err)
	}

	for _, m := range maps {
		if m.Pathname == exePath {
			return uint64(m.StartAddr), nil
		}
	}

	return 0, fmt.Errorf("executable mapping not found in /proc/%d/maps", pid)
}
