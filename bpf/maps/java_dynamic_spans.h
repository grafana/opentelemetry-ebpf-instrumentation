// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>
#include <common/trace_key.h>
#include <common/usdt_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_obi_usdt_max_spec_cnt);
    __type(key, u64);
    __type(value, u32);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_java_dynamic_probes SEC(".maps");

struct java_dynamic_context {
    u64 cookie;
    tp_info_pid_t trace;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, trace_key_t);
    __type(value, struct java_dynamic_context);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_dynamic_spans SEC(".maps");
