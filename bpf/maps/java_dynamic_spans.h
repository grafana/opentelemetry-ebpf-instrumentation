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

// Scratch async propagation state. Executor advice captures the active dynamic
// span by task identity; Runnable advice installs it on the worker and restores
// the worker's prior span when the task exits.
struct java_dynamic_task_key {
    u32 pid;
    // Scratch prototype uses System.identityHashCode(task); collisions and
    // reuse can misassociate contexts. Replace with a stable task identity.
    u32 task_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct java_dynamic_task_key);
    __type(value, struct java_dynamic_context);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_dynamic_task_contexts SEC(".maps");

enum { k_java_dynamic_task_scope_max_depth = 8 };

struct java_dynamic_task_scope_state {
    u32 depth;
    u32 overflow_depth;
};

struct java_dynamic_task_scope_key {
    u64 pid_tgid;
    u32 depth;
    u32 _pad;
};

struct java_dynamic_task_scope_frame {
    u32 captured;
    u32 had_previous;
    struct java_dynamic_context previous;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64);
    __type(value, struct java_dynamic_task_scope_state);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_dynamic_task_scopes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, struct java_dynamic_task_scope_key);
    __type(value, struct java_dynamic_task_scope_frame);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_dynamic_task_backups SEC(".maps");
