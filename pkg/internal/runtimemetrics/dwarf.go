// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"debug/dwarf"
	"fmt"
)

type runtimeOffsets struct {
	memstatsNumGC       int64
	memstatsNumForcedGC int64

	heapStatsStats     int64
	heapStatsDeltaSize int64
	largeAlloc         int64
	largeAllocCount    int64
	smallAllocCount    int64
	largeFree          int64
	largeFreeCount     int64
	smallFreeCount     int64
	numSizeClasses     int64

	gcPercent   int64
	memoryLimit int64

	schedGFreeStackSize   int64
	schedGFreeNoStackSize int64
	schedNGSys            int64
	pGFreeSize            int64
}

type dwarfInfo struct {
	data    *dwarf.Data
	types   map[dwarf.Offset]dwarf.Type
	structs map[string]*dwarf.StructType
}

func newDwarfInfo(data *dwarf.Data) (*dwarfInfo, error) {
	r := data.Reader()
	info := &dwarfInfo{
		data:    data,
		types:   map[dwarf.Offset]dwarf.Type{},
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
		info.types[ent.Offset] = typ
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
	memstats, err := i.structByName("runtime.mstats")
	if err != nil {
		return runtimeOffsets{}, err
	}
	heapStats, err := i.structByName("runtime.consistentHeapStats")
	if err != nil {
		return runtimeOffsets{}, err
	}
	heapStatsDelta, err := i.structByName("runtime.heapStatsDelta")
	if err != nil {
		return runtimeOffsets{}, err
	}
	gcController, err := i.structByName("runtime.gcControllerState")
	if err != nil {
		return runtimeOffsets{}, err
	}
	sched, err := i.structByName("runtime.schedt")
	if err != nil {
		return runtimeOffsets{}, err
	}
	p, err := i.structByName("runtime.p")
	if err != nil {
		return runtimeOffsets{}, err
	}

	var out runtimeOffsets

	if out.memstatsNumGC, _, err = i.fieldOffset(memstats, "numgc"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.memstatsNumForcedGC, _, err = i.fieldOffset(memstats, "numforcedgc"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.heapStatsStats, _, err = i.fieldOffset(memstats, "heapStats", "stats"); err != nil {
		return runtimeOffsets{}, err
	}

	out.heapStatsDeltaSize = heapStatsDelta.ByteSize
	if out.largeAlloc, _, err = i.fieldOffset(heapStatsDelta, "largeAlloc"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.largeAllocCount, _, err = i.fieldOffset(heapStatsDelta, "largeAllocCount"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.smallAllocCount, _, err = i.fieldOffset(heapStatsDelta, "smallAllocCount"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.largeFree, _, err = i.fieldOffset(heapStatsDelta, "largeFree"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.largeFreeCount, _, err = i.fieldOffset(heapStatsDelta, "largeFreeCount"); err != nil {
		return runtimeOffsets{}, err
	}
	var smallFreeType dwarf.Type
	if out.smallFreeCount, smallFreeType, err = i.fieldOffset(heapStatsDelta, "smallFreeCount"); err != nil {
		return runtimeOffsets{}, err
	}
	if arr, ok := underlyingType(smallFreeType).(*dwarf.ArrayType); ok {
		out.numSizeClasses = arr.Count
	} else {
		return runtimeOffsets{}, fmt.Errorf("runtime.heapStatsDelta.smallFreeCount is %T, expected array", smallFreeType)
	}

	if out.gcPercent, _, err = i.fieldOffset(gcController, "gcPercent"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.memoryLimit, _, err = i.fieldOffset(gcController, "memoryLimit"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.schedGFreeStackSize, _, err = i.fieldOffset(sched, "gFree", "stack", "size"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.schedGFreeNoStackSize, _, err = i.fieldOffset(sched, "gFree", "noStack", "size"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.schedNGSys, _, err = i.fieldOffset(sched, "ngsys"); err != nil {
		return runtimeOffsets{}, err
	}
	if out.pGFreeSize, _, err = i.fieldOffset(p, "gFree", "size"); err != nil {
		return runtimeOffsets{}, err
	}

	_ = heapStats
	return out, nil
}
