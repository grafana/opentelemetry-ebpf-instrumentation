// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	pointerSize          = 8
	smallAllocClassStart = 1
	sizeClassByteWidth   = 2
	maxConsecutiveFails  = 3
)

type symbols struct {
	memstats     uint64
	gcController uint64
	gomaxprocs   uint64
	allglen      uint64
	allp         uint64
	sched        uint64
	classToSize  uint64
}

type Reader struct {
	pid              app.PID
	service          svc.Attrs
	byteOrder        binary.ByteOrder
	symbols          symbols
	offsets          runtimeOffsets
	classToSize      []uint64
	mem              *os.File
	consecutiveFails int
}

func NewReader(file *exec.FileInfo) (*Reader, error) {
	if file == nil {
		return nil, errors.New("missing executable file info")
	}

	ef, closeELF, err := openExecutableELF(file)
	if err != nil {
		return nil, err
	}
	defer closeELF()

	if ef.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("unsupported Go ELF class %s", ef.Class)
	}

	baseAddr := uint64(0)
	if ef.Type == elf.ET_DYN {
		baseAddr, err = procs.FindExeBaseAddr(file.Pid)
		if err != nil {
			return nil, fmt.Errorf("reading executable base address: %w", err)
		}
	}

	syms, err := runtimeSymbols(ef, baseAddr)
	if err != nil {
		return nil, err
	}

	dw, err := ef.DWARF()
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

	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", file.Pid))
	if err != nil {
		return nil, fmt.Errorf("opening /proc/%d/mem: %w", file.Pid, err)
	}

	classToSize, err := readClassToSize(mem, ef.ByteOrder, syms.classToSize, offs.heapDelta.numSizeClasses)
	if err != nil {
		_ = mem.Close()
		return nil, err
	}

	return &Reader{
		pid:         file.Pid,
		service:     file.Service,
		byteOrder:   ef.ByteOrder,
		symbols:     syms,
		offsets:     offs,
		classToSize: classToSize,
		mem:         mem,
	}, nil
}

func openExecutableELF(file *exec.FileInfo) (*elf.File, func(), error) {
	path := file.ProExeLinkPath
	if path == "" {
		path = fmt.Sprintf("/proc/%d/exe", file.Pid)
	}
	ef, err := elf.Open(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("opening ELF %s: %w", path, err)
	}
	return ef, func() { _ = ef.Close() }, nil
}

func (r *Reader) Close() error {
	if r.mem == nil {
		return nil
	}
	err := r.mem.Close()
	r.mem = nil
	return err
}

func readClassToSize(mem io.ReaderAt, byteOrder binary.ByteOrder, addr uint64, numSizeClasses int64) ([]uint64, error) {
	if numSizeClasses <= 0 {
		return nil, fmt.Errorf("invalid numSizeClasses %d from DWARF", numSizeClasses)
	}
	buf := make([]byte, numSizeClasses*sizeClassByteWidth)
	if _, err := mem.ReadAt(buf, int64(addr)); err != nil {
		return nil, fmt.Errorf("reading size-class table: %w", err)
	}
	sizes := make([]uint64, numSizeClasses)
	for i := int64(0); i < numSizeClasses; i++ {
		sizes[i] = uint64(byteOrder.Uint16(buf[i*sizeClassByteWidth:]))
	}
	return sizes, nil
}

func runtimeSymbols(f *elf.File, baseAddr uint64) (symbols, error) {
	var out symbols
	required := map[string]*uint64{
		"runtime.memstats":     &out.memstats,
		"runtime.gcController": &out.gcController,
		"runtime.gomaxprocs":   &out.gomaxprocs,
		"runtime.allglen":      &out.allglen,
		"runtime.allp":         &out.allp,
		"runtime.sched":        &out.sched,
	}
	classToSizeAliases := []string{
		"internal/runtime/gc.SizeClassToSize", // Go 1.21+
		"runtime.class_to_size",               // older
	}

	read := func(syms []elf.Symbol) {
		for _, sym := range syms {
			if dst, ok := required[sym.Name]; ok && *dst == 0 {
				*dst = baseAddr + sym.Value
			}
			for _, name := range classToSizeAliases {
				if sym.Name == name && out.classToSize == 0 {
					out.classToSize = baseAddr + sym.Value
				}
			}
		}
	}

	if syms, err := f.Symbols(); err == nil {
		read(syms)
	} else if !errors.Is(err, elf.ErrNoSymbols) {
		return symbols{}, err
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		read(syms)
	} else if !errors.Is(err, elf.ErrNoSymbols) {
		return symbols{}, err
	}

	for name, addr := range required {
		if *addr == 0 {
			return symbols{}, fmt.Errorf("runtime symbol %s not found", name)
		}
	}
	if out.classToSize == 0 {
		return symbols{}, fmt.Errorf("size-class table symbol not found (tried %v)", classToSizeAliases)
	}
	return out, nil
}

func (r *Reader) ReadSnapshot() (Snapshot, error) {
	if r.mem == nil {
		return Snapshot{}, errors.New("reader closed")
	}

	hs, err := r.readHeapStats(r.mem)
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}

	numGC, err := r.readUint32(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.numGC))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	numForcedGC, err := r.readUint32(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.numForcedGC))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	gomaxprocs, err := r.readInt32(r.mem, r.symbols.gomaxprocs)
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	gcPercent, err := r.readInt32(r.mem, r.symbols.gcController+uint64(r.offsets.gcController.gcPercent))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	memLimit, err := r.readInt64(r.mem, r.symbols.gcController+uint64(r.offsets.gcController.memoryLimit))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	heapInUse, err := r.readUint64(r.mem, r.symbols.gcController+uint64(r.offsets.gcController.heapInUse))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	heapGoal, err := r.readUint64(r.mem, r.symbols.gcController+uint64(r.offsets.gcController.gcPercentHeapGoal))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	stacksSys, err := r.readUint64(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.stacksSys))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	mspanSys, err := r.readUint64(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.mspanSys))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	mcacheSys, err := r.readUint64(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.mcacheSys))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	buckhashSys, err := r.readUint64(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.buckhashSys))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	gcMiscSys, err := r.readUint64(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.gcMiscSys))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	otherSys, err := r.readUint64(r.mem, r.symbols.memstats+uint64(r.offsets.memstats.otherSys))
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}
	goroutines, err := r.readGoroutineCount(r.mem)
	if err != nil {
		return Snapshot{}, r.observeFailure(err)
	}

	r.consecutiveFails = 0

	var limit *int64
	if memLimit < math.MaxInt64 {
		limit = &memLimit
	}

	total := uint64(numGC)
	forced := uint64(numForcedGC)
	if forced > total {
		return Snapshot{}, fmt.Errorf("torn GC counter read (forced=%d > total=%d)", forced, total)
	}

	var gogc *int64
	if gcPercent >= 0 {
		v := int64(gcPercent)
		gogc = &v
	}

	usedStack := saturatingAdd(uint64(hs.inStacks), stacksSys)
	usedOther := heapInUse + mspanSys + mcacheSys + buckhashSys + gcMiscSys + otherSys + uint64(hs.inWorkBufs)

	return Snapshot{
		Service:           r.service,
		PID:               r.pid,
		Time:              time.Now(),
		MemoryLimit:       limit,
		MemoryAllocated:   hs.allocated,
		MemoryAllocations: hs.allocations,
		MemoryUsedStack:   usedStack,
		MemoryUsedOther:   usedOther,
		MemoryGCGoal:      heapGoal,
		GCCyclesAutomatic: total - forced,
		GCCyclesForced:    forced,
		GoroutineCount:    goroutines,
		ProcessorLimit:    int64(gomaxprocs),
		GOGC:              gogc,
	}, nil
}

func saturatingAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func (r *Reader) failing() bool {
	return r.consecutiveFails >= maxConsecutiveFails
}

func (r *Reader) observeFailure(err error) error {
	r.consecutiveFails++
	return err
}

type heapStatsAggregate struct {
	allocated   uint64
	allocations uint64
	inStacks    int64
	inWorkBufs  int64
}

func (r *Reader) readHeapStats(mem io.ReaderAt) (heapStatsAggregate, error) {
	statsAddr := r.symbols.memstats + uint64(r.offsets.memstats.heapStats)
	stride := uint64(r.offsets.heapDelta.stride)

	var out heapStatsAggregate
	for gen := range numHeapStatGenerations {
		base := statsAddr + uint64(gen)*stride
		largeAlloc, err := r.readUint64(mem, base+uint64(r.offsets.heapDelta.largeAlloc))
		if err != nil {
			return heapStatsAggregate{}, err
		}
		largeAllocCount, err := r.readUint64(mem, base+uint64(r.offsets.heapDelta.largeAllocCount))
		if err != nil {
			return heapStatsAggregate{}, err
		}
		out.allocated += largeAlloc
		out.allocations += largeAllocCount

		for i := int64(smallAllocClassStart); i < r.offsets.heapDelta.numSizeClasses; i++ {
			allocCount, err := r.readUint64(mem, base+uint64(r.offsets.heapDelta.smallAllocCount+i*8))
			if err != nil {
				return heapStatsAggregate{}, err
			}
			out.allocated += allocCount * r.classToSize[i]
			out.allocations += allocCount
		}

		inStacks, err := r.readInt64(mem, base+uint64(r.offsets.heapDelta.inStacks))
		if err != nil {
			return heapStatsAggregate{}, err
		}
		inWorkBufs, err := r.readInt64(mem, base+uint64(r.offsets.heapDelta.inWorkBufs))
		if err != nil {
			return heapStatsAggregate{}, err
		}
		out.inStacks += inStacks
		out.inWorkBufs += inWorkBufs
	}

	return out, nil
}

func (r *Reader) readGoroutineCount(mem io.ReaderAt) (int64, error) {
	allglen, err := r.readUint64(mem, r.symbols.allglen)
	if err != nil {
		return 0, err
	}
	freeStack, err := r.readInt32(mem, r.symbols.sched+uint64(r.offsets.sched.gFreeStackSize))
	if err != nil {
		return 0, err
	}
	freeNoStack, err := r.readInt32(mem, r.symbols.sched+uint64(r.offsets.sched.gFreeNoStackSize))
	if err != nil {
		return 0, err
	}
	ngsys, err := r.readInt32(mem, r.symbols.sched+uint64(r.offsets.sched.ngsys))
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
		free, err := r.readInt32(mem, pp+uint64(r.offsets.p.gFreeSize))
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
