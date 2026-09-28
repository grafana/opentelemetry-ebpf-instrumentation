// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/go_addr_key.h>
#include <common/maps/obi_usdt_specs.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
#include <common/trace_helpers.h>
#include <maps/go_trace_map.h>
#include <shared/obi_ctx.h>

volatile const u64 go_dynamic_span_ttl = 0;

enum { k_go_dynamic_unwind_limit = 32 };

struct go_dynamic_frame_key {
    go_addr_key_t goroutine;
    u64 id;
};

struct go_dynamic_frame {
    tp_info_t current;
    tp_info_t previous;
    u64 parent;
    u64 sdk_parent_id;
    u64 cookie;
    u32 stack_off;
    u32 spec_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_dynamic_span_heads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct go_dynamic_frame_key);
    __type(value, struct go_dynamic_frame);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_dynamic_span_frames SEC(".maps");

SCRATCH_MEM_TYPED(go_dynamic_frame_scratch, struct go_dynamic_frame)

static __always_inline bool go_dynamic_valid_context(const tp_info_t *tp) {
    return tp && valid_trace(tp->trace_id) && valid_span(tp->span_id);
}

static __always_inline void go_dynamic_restore(const go_addr_key_t *goroutine,
                                               const struct go_dynamic_frame *frame) {
    const tp_info_t *current = bpf_map_lookup_elem(&go_trace_map, goroutine);
    if (current && *(const u64 *)current->span_id == *(const u64 *)frame->current.span_id) {
        if (go_dynamic_valid_context(&frame->previous)) {
            bpf_map_update_elem(&go_trace_map, goroutine, &frame->previous, BPF_ANY);
        } else {
            bpf_map_delete_elem(&go_trace_map, goroutine);
        }
    }
    if (frame->parent) {
        bpf_map_update_elem(&go_dynamic_span_heads, goroutine, &frame->parent, BPF_ANY);
    } else {
        bpf_map_delete_elem(&go_dynamic_span_heads, goroutine);
    }
}

static __always_inline bool go_dynamic_frame_active(const struct go_dynamic_frame *frame) {
    if (bpf_ktime_get_ns() - frame->current.ts > go_dynamic_span_ttl) {
        return false;
    }
    // A detached probe's spec is cleared or reused with a different cookie.
    if (frame->cookie) {
        const struct obi_usdt_spec *spec = bpf_map_lookup_elem(&obi_usdt_specs, &frame->spec_id);
        return spec && spec->cookie == frame->cookie;
    }
    return true;
}

// Unwind lost returns, stack-growth retries, and detached or expired probes.
static __always_inline void go_dynamic_span_prune(const go_addr_key_t *goroutine, u32 stack_off) {
    if (!go_dynamic_span_ttl) {
        return;
    }
    struct go_dynamic_frame_key key = {.goroutine = *goroutine};
    for (u32 i = 0; i < k_go_dynamic_unwind_limit; i++) {
        const u64 *head = bpf_map_lookup_elem(&go_dynamic_span_heads, goroutine);
        if (!head) {
            return;
        }
        key.id = *head;
        const struct go_dynamic_frame *frame = bpf_map_lookup_elem(&go_dynamic_span_frames, &key);
        if (!frame) {
            const tp_info_t *current = bpf_map_lookup_elem(&go_trace_map, goroutine);
            if (current && *(const u64 *)current->span_id == key.id) {
                bpf_map_delete_elem(&go_trace_map, goroutine);
            }
            bpf_map_delete_elem(&go_dynamic_span_heads, goroutine);
            return;
        }
        if (go_dynamic_frame_active(frame) && (!stack_off || frame->stack_off < stack_off)) {
            return;
        }
        go_dynamic_restore(goroutine, frame);
        bpf_map_delete_elem(&go_dynamic_span_frames, &key);
    }
    bpf_map_delete_elem(&go_dynamic_span_heads, goroutine);
}

static __always_inline bool go_dynamic_span_push(const go_addr_key_t *goroutine,
                                                 const struct go_dynamic_frame *frame) {
    const struct go_dynamic_frame_key key = {.goroutine = *goroutine,
                                             .id = *(const u64 *)frame->current.span_id};
    if (bpf_map_update_elem(&go_dynamic_span_frames, &key, frame, BPF_ANY)) {
        return false;
    }
    if (bpf_map_update_elem(&go_dynamic_span_heads, goroutine, &key.id, BPF_ANY)) {
        bpf_map_delete_elem(&go_dynamic_span_frames, &key);
        return false;
    }
    bpf_map_update_elem(&go_trace_map, goroutine, &frame->current, BPF_ANY);
    return true;
}

static __always_inline void go_dynamic_span_exit(const go_addr_key_t *goroutine) {
    struct go_dynamic_frame_key key = {.goroutine = *goroutine};
    for (u32 i = 0; i < k_go_dynamic_unwind_limit; i++) {
        const u64 *head = bpf_map_lookup_elem(&go_dynamic_span_heads, goroutine);
        if (!head) {
            break;
        }
        key.id = *head;
        const struct go_dynamic_frame *frame = bpf_map_lookup_elem(&go_dynamic_span_frames, &key);
        if (!frame) {
            break;
        }
        const u64 parent = frame->parent;
        bpf_map_update_elem(&go_dynamic_span_heads, goroutine, &parent, BPF_ANY);
        bpf_map_delete_elem(&go_dynamic_span_frames, &key);
    }
    bpf_map_delete_elem(&go_dynamic_span_heads, goroutine);
    bpf_map_delete_elem(&go_trace_map, goroutine);
}

static __always_inline void go_dynamic_span_inherit(const go_addr_key_t *goroutine,
                                                    const go_addr_key_t *parent) {
    go_dynamic_span_exit(goroutine);
    go_dynamic_span_prune(parent, 0);
    const tp_info_t *context = bpf_map_lookup_elem(&go_trace_map, parent);
    if (!go_dynamic_valid_context(context)) {
        return;
    }
    struct go_dynamic_frame *frame = go_dynamic_frame_scratch_mem();
    if (!frame) {
        return;
    }
    bpf_memset(frame, 0, sizeof(*frame));
    frame->current = *context;
    frame->current.ts = bpf_ktime_get_ns();
    const u64 *head = bpf_map_lookup_elem(&go_dynamic_span_heads, parent);
    if (head && *head == *(const u64 *)context->span_id) {
        const struct go_dynamic_frame_key key = {.goroutine = *parent, .id = *head};
        const struct go_dynamic_frame *source = bpf_map_lookup_elem(&go_dynamic_span_frames, &key);
        if (source) {
            frame->sdk_parent_id = source->sdk_parent_id;
            frame->cookie = source->cookie;
            frame->spec_id = source->spec_id;
        }
    }
    go_dynamic_span_push(goroutine, frame);
}
