// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>
#include <common/usdt_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_obi_usdt_max_spec_cnt);
    __type(key, u64);
    __type(value, u32);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_node_dynamic_probes SEC(".maps");

// Full request context for Node async callbacks, including sampling flags.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, tp_info_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} node_dynamic_requests SEC(".maps");

struct node_dynamic_key {
    u64 pid;
    u64 invocation;
};

struct node_dynamic_context {
    u64 cookie;
    tp_info_pid_t trace;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct node_dynamic_key);
    __type(value, struct node_dynamic_context);
    __uint(pinning, OBI_PIN_INTERNAL);
} node_dynamic_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct node_dynamic_key);
    __uint(pinning, OBI_PIN_INTERNAL);
} node_dynamic_active SEC(".maps");

static __always_inline tp_info_pid_t *node_dynamic_parent(u64 pid_tgid) {
    const struct node_dynamic_key *key = bpf_map_lookup_elem(&node_dynamic_active, &pid_tgid);
    if (!key) {
        return NULL;
    }
    struct node_dynamic_context *context = bpf_map_lookup_elem(&node_dynamic_calls, key);
    if (!context || !bpf_map_lookup_elem(&obi_node_dynamic_probes, &context->cookie)) {
        return NULL;
    }
    return &context->trace;
}
