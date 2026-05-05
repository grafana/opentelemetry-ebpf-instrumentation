// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"debug/dwarf"
	"fmt"
)

const numHeapStatGenerations = 3 // runtime.consistentHeapStats.stats length

type memstatsOffsets struct {
	numGC       int64
	numForcedGC int64
	heapStats   int64
	stacksSys   int64
	mspanSys    int64
	mcacheSys   int64
	buckhashSys int64
	gcMiscSys   int64
	otherSys    int64
}

type heapStatsDeltaOffsets struct {
	stride          int64
	largeAlloc      int64
	largeAllocCount int64
	smallAllocCount int64
	largeFree       int64
	largeFreeCount  int64
	smallFreeCount  int64
	numSizeClasses  int64
	inStacks        int64
	inWorkBufs      int64
}

type gcControllerOffsets struct {
	gcPercent         int64
	memoryLimit       int64
	heapInUse         int64
	gcPercentHeapGoal int64
}

type schedOffsets struct {
	gFreeStackSize   int64
	gFreeNoStackSize int64
	ngsys            int64
}

type pOffsets struct {
	gFreeSize int64
}

type runtimeOffsets struct {
	memstats     memstatsOffsets
	heapDelta    heapStatsDeltaOffsets
	gcController gcControllerOffsets
	sched        schedOffsets
	p            pOffsets
}

type dwarfInfo struct {
	data    *dwarf.Data
	structs map[string]*dwarf.StructType
}

func newDwarfInfo(data *dwarf.Data) (*dwarfInfo, error) {
	r := data.Reader()
	info := &dwarfInfo{
		data:    data,
		structs: map[string]*dwarf.StructType{},
	}

	for {
		ent, err := r.Next()
		if err != nil {
			return nil, err
		}
		if ent == nil {
			break
		}
		if ent.Tag != dwarf.TagStructType {
			continue
		}

		typ, err := data.Type(ent.Offset)
		if err != nil {
			continue
		}
		if st, ok := typ.(*dwarf.StructType); ok && st.StructName != "" {
			info.structs[st.StructName] = st
		}
	}

	return info, nil
}

func (i *dwarfInfo) structByName(name string) (*dwarf.StructType, error) {
	st, ok := i.structs[name]
	if !ok {
		return nil, fmt.Errorf("DWARF struct %s not found", name)
	}
	return st, nil
}

func (i *dwarfInfo) fieldOffset(st *dwarf.StructType, path ...string) (int64, dwarf.Type, error) {
	var offset int64
	var typ dwarf.Type = st

	for _, fieldName := range path {
		cur, ok := underlyingType(typ).(*dwarf.StructType)
		if !ok {
			return 0, nil, fmt.Errorf("%s is not a struct", fieldName)
		}
		found := false
		for _, field := range cur.Field {
			if field.Name != fieldName {
				continue
			}
			offset += field.ByteOffset
			typ = field.Type
			found = true
			break
		}
		if !found {
			return 0, nil, fmt.Errorf("field %s not found in %s", fieldName, cur.StructName)
		}
	}

	return offset, typ, nil
}

func underlyingType(typ dwarf.Type) dwarf.Type {
	for {
		switch t := typ.(type) {
		case *dwarf.TypedefType:
			typ = t.Type
		case *dwarf.QualType:
			typ = t.Type
		default:
			return typ
		}
	}
}

func (i *dwarfInfo) runtimeOffsets() (runtimeOffsets, error) {
	var out runtimeOffsets
	if err := i.readMemstatsOffsets(&out.memstats); err != nil {
		return runtimeOffsets{}, err
	}
	if err := i.readHeapStatsDeltaOffsets(&out.heapDelta); err != nil {
		return runtimeOffsets{}, err
	}
	if err := i.readGCControllerOffsets(&out.gcController); err != nil {
		return runtimeOffsets{}, err
	}
	if err := i.readSchedOffsets(&out.sched); err != nil {
		return runtimeOffsets{}, err
	}
	if err := i.readPOffsets(&out.p); err != nil {
		return runtimeOffsets{}, err
	}
	return out, nil
}

func (i *dwarfInfo) readMemstatsOffsets(out *memstatsOffsets) error {
	memstats, err := i.structByName("runtime.mstats")
	if err != nil {
		return err
	}
	if out.numGC, _, err = i.fieldOffset(memstats, "numgc"); err != nil {
		return err
	}
	if out.numForcedGC, _, err = i.fieldOffset(memstats, "numforcedgc"); err != nil {
		return err
	}
	if out.heapStats, _, err = i.fieldOffset(memstats, "heapStats", "stats"); err != nil {
		return err
	}
	if out.stacksSys, _, err = i.fieldOffset(memstats, "stacks_sys"); err != nil {
		return err
	}
	if out.mspanSys, _, err = i.fieldOffset(memstats, "mspan_sys"); err != nil {
		return err
	}
	if out.mcacheSys, _, err = i.fieldOffset(memstats, "mcache_sys"); err != nil {
		return err
	}
	if out.buckhashSys, _, err = i.fieldOffset(memstats, "buckhash_sys"); err != nil {
		return err
	}
	if out.gcMiscSys, _, err = i.fieldOffset(memstats, "gcMiscSys"); err != nil {
		return err
	}
	if out.otherSys, _, err = i.fieldOffset(memstats, "other_sys"); err != nil {
		return err
	}
	return nil
}

func (i *dwarfInfo) readHeapStatsDeltaOffsets(out *heapStatsDeltaOffsets) error {
	heapStatsDelta, err := i.structByName("runtime.heapStatsDelta")
	if err != nil {
		return err
	}
	out.stride = heapStatsDelta.ByteSize
	if out.largeAlloc, _, err = i.fieldOffset(heapStatsDelta, "largeAlloc"); err != nil {
		return err
	}
	if out.largeAllocCount, _, err = i.fieldOffset(heapStatsDelta, "largeAllocCount"); err != nil {
		return err
	}
	if out.smallAllocCount, _, err = i.fieldOffset(heapStatsDelta, "smallAllocCount"); err != nil {
		return err
	}
	if out.largeFree, _, err = i.fieldOffset(heapStatsDelta, "largeFree"); err != nil {
		return err
	}
	if out.largeFreeCount, _, err = i.fieldOffset(heapStatsDelta, "largeFreeCount"); err != nil {
		return err
	}
	smallFreeOffset, smallFreeType, err := i.fieldOffset(heapStatsDelta, "smallFreeCount")
	if err != nil {
		return err
	}
	out.smallFreeCount = smallFreeOffset
	arr, ok := underlyingType(smallFreeType).(*dwarf.ArrayType)
	if !ok {
		return fmt.Errorf("runtime.heapStatsDelta.smallFreeCount is %T, expected array", smallFreeType)
	}
	out.numSizeClasses = arr.Count
	if out.inStacks, _, err = i.fieldOffset(heapStatsDelta, "inStacks"); err != nil {
		return err
	}
	if out.inWorkBufs, _, err = i.fieldOffset(heapStatsDelta, "inWorkBufs"); err != nil {
		return err
	}
	return nil
}

func (i *dwarfInfo) readGCControllerOffsets(out *gcControllerOffsets) error {
	gcController, err := i.structByName("runtime.gcControllerState")
	if err != nil {
		return err
	}
	if out.gcPercent, _, err = i.fieldOffset(gcController, "gcPercent"); err != nil {
		return err
	}
	if out.memoryLimit, _, err = i.fieldOffset(gcController, "memoryLimit"); err != nil {
		return err
	}
	if out.heapInUse, _, err = i.fieldOffset(gcController, "heapInUse"); err != nil {
		return err
	}
	if out.gcPercentHeapGoal, _, err = i.fieldOffset(gcController, "gcPercentHeapGoal"); err != nil {
		return err
	}
	return nil
}

func (i *dwarfInfo) readSchedOffsets(out *schedOffsets) error {
	sched, err := i.structByName("runtime.schedt")
	if err != nil {
		return err
	}
	if out.gFreeStackSize, _, err = i.fieldOffset(sched, "gFree", "stack", "size"); err != nil {
		return err
	}
	if out.gFreeNoStackSize, _, err = i.fieldOffset(sched, "gFree", "noStack", "size"); err != nil {
		return err
	}
	if out.ngsys, _, err = i.fieldOffset(sched, "ngsys"); err != nil {
		return err
	}
	return nil
}

func (i *dwarfInfo) readPOffsets(out *pOffsets) error {
	p, err := i.structByName("runtime.p")
	if err != nil {
		return err
	}
	if out.gFreeSize, _, err = i.fieldOffset(p, "gFree", "size"); err != nil {
		return err
	}
	return nil
}
