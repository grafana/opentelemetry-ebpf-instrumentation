// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	pointerSize          = 8
	smallAllocClassStart = 1
)

var sizeClassToSize = [...]uint64{
	0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208,
	224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704,
	768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688, 3072,
	3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728,
	10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760,
	24576, 27264, 28672, 32768,
}

type symbols struct {
	memstats     uint64
	gcController uint64
	gomaxprocs   uint64
	allglen      uint64
	allp         uint64
	sched        uint64
}

type Reader struct {
	pid       app.PID
	service   exec.FileInfo
	byteOrder binary.ByteOrder
	symbols   symbols
	offsets   runtimeOffsets
}

func NewReader(file *exec.FileInfo) (*Reader, error) {
	if file == nil {
		return nil, errors.New("missing executable information")
	}

	elfFile, closeELF, err := openExecutableELF(file)
	if err != nil {
		return nil, err
	}
	defer closeELF()

	if elfFile.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("unsupported Go ELF class %s", elfFile.Class)
	}

	baseAddr := uint64(0)
	if elfFile.Type == elf.ET_DYN {
		baseAddr, err = procs.FindExeBaseAddr(file.Pid)
		if err != nil {
			return nil, fmt.Errorf("reading executable base address: %w", err)
		}
	}

	syms, err := runtimeSymbols(elfFile, baseAddr)
	if err != nil {
		return nil, err
	}

	dw, err := elfFile.DWARF()
	if err != nil {
		return nil, fmt.Errorf("reading DWARF offsets: %w", err)
	}
	info, err := newDwarfInfo(dw)
	if err != nil {
		return nil, fmt.Errorf("indexing DWARF offsets: %w", err)
	}
	offs, err := info.runtimeOffsets()
	if err != nil {
		return nil, fmt.Errorf("reading runtime DWARF offsets: %w", err)
	}
	if offs.numSizeClasses > int64(len(sizeClassToSize)) {
		return nil, fmt.Errorf("unsupported Go size class count %d", offs.numSizeClasses)
	}

	return &Reader{
		pid:       file.Pid,
		service:   *file,
		byteOrder: elfFile.ByteOrder,
		symbols:   syms,
		offsets:   offs,
	}, nil
}

func openExecutableELF(file *exec.FileInfo) (*elf.File, func(), error) {
	if file.ProExeLinkPath != "" {
		elfFile, err := elf.Open(file.ProExeLinkPath)
		if err == nil {
			return elfFile, func() { _ = elfFile.Close() }, nil
		}
		if file.ELF == nil {
			return nil, nil, fmt.Errorf("opening executable ELF %s: %w", file.ProExeLinkPath, err)
		}
	}

	if file.ELF == nil {
		return nil, nil, errors.New("missing executable ELF")
	}
	return file.ELF, func() {}, nil
}

func runtimeSymbols(f *elf.File, baseAddr uint64) (symbols, error) {
	names := map[string]*uint64{}
	var out symbols
	names["runtime.memstats"] = &out.memstats
	names["runtime.gcController"] = &out.gcController
	names["runtime.gomaxprocs"] = &out.gomaxprocs
	names["runtime.allglen"] = &out.allglen
	names["runtime.allp"] = &out.allp
	names["runtime.sched"] = &out.sched

	read := func(syms []elf.Symbol) {
		for _, sym := range syms {
			dst, ok := names[sym.Name]
			if !ok {
				continue
			}
			*dst = baseAddr + sym.Value
		}
	}

	if syms, err := f.Symbols(); err == nil {
		read(syms)
	} else if !errors.Is(err, elf.ErrNoSymbols) {
		return symbols{}, fmt.Errorf("reading symbols: %w", err)
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		read(syms)
	} else if !errors.Is(err, elf.ErrNoSymbols) {
		return symbols{}, fmt.Errorf("reading dynamic symbols: %w", err)
	}

	for name, addr := range names {
		if *addr == 0 {
			return symbols{}, fmt.Errorf("runtime symbol %s not found", name)
		}
	}
	return out, nil
}

func (r *Reader) ReadSnapshot() (Snapshot, error) {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", r.pid))
	if err != nil {
		return Snapshot{}, err
	}
	defer mem.Close()

	allocated, allocations, err := r.readHeapStats(mem)
	if err != nil {
		return Snapshot{}, err
	}

	numGC, err := r.readUint32(mem, r.symbols.memstats+uint64(r.offsets.memstatsNumGC))
	if err != nil {
		return Snapshot{}, err
	}
	numForcedGC, err := r.readUint32(mem, r.symbols.memstats+uint64(r.offsets.memstatsNumForcedGC))
	if err != nil {
		return Snapshot{}, err
	}
	gomaxprocs, err := r.readInt32(mem, r.symbols.gomaxprocs)
	if err != nil {
		return Snapshot{}, err
	}
	gogc, err := r.readInt32(mem, r.symbols.gcController+uint64(r.offsets.gcPercent))
	if err != nil {
		return Snapshot{}, err
	}
	memLimit, err := r.readInt64(mem, r.symbols.gcController+uint64(r.offsets.memoryLimit))
	if err != nil {
		return Snapshot{}, err
	}
	goroutines, err := r.readGoroutineCount(mem)
	if err != nil {
		return Snapshot{}, err
	}

	var limit *int64
	if memLimit != MaxInt64 {
		limit = &memLimit
	}

	forced := uint64(numForcedGC)
	automatic := uint64(numGC)
	if forced <= automatic {
		automatic -= forced
	}

	return Snapshot{
		Service:           r.service.Service,
		PID:               r.pid,
		Time:              time.Now(),
		MemoryLimit:       limit,
		MemoryAllocated:   allocated,
		MemoryAllocations: allocations,
		GCCyclesAutomatic: automatic,
		GCCyclesForced:    forced,
		GoroutineCount:    goroutines,
		ProcessorLimit:    int64(gomaxprocs),
		GOGC:              int64(gogc),
	}, nil
}

func (r *Reader) readHeapStats(mem io.ReaderAt) (allocated uint64, allocations uint64, err error) {
	var totalAllocated, totalAllocs uint64
	statsAddr := r.symbols.memstats + uint64(r.offsets.heapStatsStats)

	for gen := int64(0); gen < 3; gen++ {
		base := statsAddr + uint64(gen*r.offsets.heapStatsDeltaSize)
		largeAlloc, err := r.readUint64(mem, base+uint64(r.offsets.largeAlloc))
		if err != nil {
			return 0, 0, err
		}
		largeAllocCount, err := r.readUint64(mem, base+uint64(r.offsets.largeAllocCount))
		if err != nil {
			return 0, 0, err
		}
		totalAllocated += largeAlloc
		totalAllocs += largeAllocCount

		for i := int64(smallAllocClassStart); i < r.offsets.numSizeClasses; i++ {
			size := sizeClassToSize[i]
			allocCount, err := r.readUint64(mem, base+uint64(r.offsets.smallAllocCount+i*8))
			if err != nil {
				return 0, 0, err
			}
			totalAllocated += allocCount * size
			totalAllocs += allocCount
		}
	}

	return totalAllocated, totalAllocs, nil
}

func (r *Reader) readGoroutineCount(mem io.ReaderAt) (int64, error) {
	allglen, err := r.readUint64(mem, r.symbols.allglen)
	if err != nil {
		return 0, err
	}
	freeStack, err := r.readInt32(mem, r.symbols.sched+uint64(r.offsets.schedGFreeStackSize))
	if err != nil {
		return 0, err
	}
	freeNoStack, err := r.readInt32(mem, r.symbols.sched+uint64(r.offsets.schedGFreeNoStackSize))
	if err != nil {
		return 0, err
	}
	ngsys, err := r.readInt32(mem, r.symbols.sched+uint64(r.offsets.schedNGSys))
	if err != nil {
		return 0, err
	}

	allpData, allpLen, err := r.readSlice(mem, r.symbols.allp)
	if err != nil {
		return 0, err
	}

	n := int64(allglen) - int64(freeStack) - int64(freeNoStack) - int64(ngsys)
	for i := uint64(0); i < allpLen; i++ {
		pp, err := r.readUint64(mem, allpData+i*pointerSize)
		if err != nil {
			return 0, err
		}
		if pp == 0 {
			continue
		}
		free, err := r.readInt32(mem, pp+uint64(r.offsets.pGFreeSize))
		if err != nil {
			return 0, err
		}
		n -= int64(free)
	}

	if n < 1 {
		n = 1
	}
	return n, nil
}

func (r *Reader) readSlice(mem io.ReaderAt, addr uint64) (data uint64, length uint64, err error) {
	hdr := make([]byte, pointerSize*3)
	if _, err := mem.ReadAt(hdr, int64(addr)); err != nil {
		return 0, 0, err
	}
	return r.byteOrder.Uint64(hdr[0:8]), r.byteOrder.Uint64(hdr[8:16]), nil
}

func (r *Reader) readUint64(mem io.ReaderAt, addr uint64) (uint64, error) {
	buf := make([]byte, 8)
	if _, err := mem.ReadAt(buf, int64(addr)); err != nil {
		return 0, err
	}
	return r.byteOrder.Uint64(buf), nil
}

func (r *Reader) readInt64(mem io.ReaderAt, addr uint64) (int64, error) {
	v, err := r.readUint64(mem, addr)
	return int64(v), err
}

func (r *Reader) readUint32(mem io.ReaderAt, addr uint64) (uint32, error) {
	buf := make([]byte, 4)
	if _, err := mem.ReadAt(buf, int64(addr)); err != nil {
		return 0, err
	}
	return r.byteOrder.Uint32(buf), nil
}

func (r *Reader) readInt32(mem io.ReaderAt, addr uint64) (int32, error) {
	v, err := r.readUint32(mem, addr)
	return int32(v), err
}
