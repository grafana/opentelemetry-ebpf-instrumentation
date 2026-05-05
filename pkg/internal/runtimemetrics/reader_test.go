// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func TestOpenExecutableELFReopensClosedFile(t *testing.T) {
	pid := app.PID(os.Getpid())
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	closedELF, err := elf.Open(exePath)
	require.NoError(t, err)
	require.NoError(t, closedELF.Close())

	openedELF, closeELF, err := openExecutableELF(&exec.FileInfo{
		Pid:            pid,
		ProExeLinkPath: exePath,
		ELF:            closedELF,
	})
	require.NoError(t, err)
	defer closeELF()

	assert.Equal(t, elf.ELFCLASS64, openedELF.Class)
}

func TestReadHeapStats(t *testing.T) {
	mem := make([]byte, 4096)
	reader := Reader{
		byteOrder: binary.LittleEndian,
		symbols: symbols{
			memstats: 512,
		},
		offsets: runtimeOffsets{
			heapStatsStats:     64,
			heapStatsDeltaSize: 256,
			largeAlloc:         0,
			largeAllocCount:    8,
			smallAllocCount:    16,
			largeFree:          96,
			largeFreeCount:     104,
			smallFreeCount:     112,
			numSizeClasses:     3,
		},
	}

	stats := int(reader.symbols.memstats + uint64(reader.offsets.heapStatsStats))
	put64(mem, stats+int(reader.offsets.largeAlloc), 1024)
	put64(mem, stats+int(reader.offsets.largeAllocCount), 2)
	put64(mem, stats+int(reader.offsets.smallAllocCount)+8, 3)
	put64(mem, stats+int(reader.offsets.smallAllocCount)+16, 4)
	put64(mem, stats+int(reader.offsets.largeFree), 99)
	put64(mem, stats+int(reader.offsets.largeFreeCount), 1)
	put64(mem, stats+int(reader.offsets.smallFreeCount)+8, 1)

	allocated, allocations, err := reader.readHeapStats(bytes.NewReader(mem))
	require.NoError(t, err)

	assert.Equal(t, uint64(1024+3*8+4*16), allocated)
	assert.Equal(t, uint64(2+3+4), allocations)
}

func TestReadGoroutineCount(t *testing.T) {
	mem := make([]byte, 4096)
	reader := Reader{
		byteOrder: binary.LittleEndian,
		symbols: symbols{
			allglen: 100,
			sched:   200,
			allp:    300,
		},
		offsets: runtimeOffsets{
			schedGFreeStackSize:   0,
			schedGFreeNoStackSize: 4,
			schedNGSys:            8,
			pGFreeSize:            16,
		},
	}

	put64(mem, int(reader.symbols.allglen), 10)
	put32(mem, int(reader.symbols.sched+uint64(reader.offsets.schedGFreeStackSize)), 2)
	put32(mem, int(reader.symbols.sched+uint64(reader.offsets.schedGFreeNoStackSize)), 1)
	put32(mem, int(reader.symbols.sched+uint64(reader.offsets.schedNGSys)), 1)

	allpData := uint64(512)
	put64(mem, int(reader.symbols.allp), allpData)
	put64(mem, int(reader.symbols.allp)+8, 2)
	put64(mem, int(reader.symbols.allp)+16, 2)

	p0 := uint64(700)
	p1 := uint64(800)
	put64(mem, int(allpData), p0)
	put64(mem, int(allpData)+8, p1)
	put32(mem, int(p0)+int(reader.offsets.pGFreeSize), 1)
	put32(mem, int(p1)+int(reader.offsets.pGFreeSize), 2)

	got, err := reader.readGoroutineCount(bytes.NewReader(mem))
	require.NoError(t, err)

	assert.Equal(t, int64(3), got)
}

func put64(buf []byte, offset int, value uint64) {
	binary.LittleEndian.PutUint64(buf[offset:offset+8], value)
}

func put32(buf []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(buf[offset:offset+4], value)
}
