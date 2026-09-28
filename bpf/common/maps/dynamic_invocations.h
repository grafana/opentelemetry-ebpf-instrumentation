// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <common/usdt_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_obi_usdt_max_spec_cnt);
    __type(key, u64);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_dynamic_invocations SEC(".maps");
