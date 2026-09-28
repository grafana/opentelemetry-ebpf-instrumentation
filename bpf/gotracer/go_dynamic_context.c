// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <common/preempt_guard.h>
#include <gotracer/go_common.h>
#include <shared/obi_ctx.h>

struct dynamic_sdk_context {
    go_addr_key_t goroutine;
    tp_info_t previous;
    tp_info_t current;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, struct dynamic_sdk_context);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} dynamic_sdk_contexts SEC(".maps");

SEC("uprobe/sdk_tracer_start_return")
int GUARDED_PROG(obi_uprobe_sdk_tracer_start_return, struct pt_regs *, ctx) {
    off_table_t *offsets = get_offsets_table();
    const u64 span_type = go_offset_of(offsets, (go_offset){.v = _sdk_recording_span_type});
    const u64 span_offset =
        go_offset_of(offsets, (go_offset){.v = _sdk_recording_span_context_pos});
    const u64 trace_offset = go_offset_of(offsets, (go_offset){.v = _span_context_trace_id_pos});
    const u64 id_offset = go_offset_of(offsets, (go_offset){.v = _span_context_span_id_pos});
    if (span_type == (u64)-1 || span_offset == (u64)-1 || trace_offset == (u64)-1 ||
        id_offset == (u64)-1 || (u64)GO_PARAM3(ctx) != span_type) {
        return 0;
    }

    unsigned char *span = GO_PARAM4(ctx);
    struct dynamic_sdk_context state = {};
    go_addr_key_from_id(&state.goroutine, GOROUTINE_PTR(ctx));
    if (bpf_probe_read_user(state.current.trace_id,
                            sizeof(state.current.trace_id),
                            span + span_offset + trace_offset) ||
        bpf_probe_read_user(
            state.current.span_id, sizeof(state.current.span_id), span + span_offset + id_offset)) {
        return 0;
    }
    state.current.ts = bpf_ktime_get_ns();
    const u64 flags_offset = go_offset_of(offsets, (go_offset){.v = _span_context_trace_flags_pos});
    if (flags_offset != (u64)-1) {
        bpf_probe_read_user(
            &state.current.flags, sizeof(state.current.flags), span + span_offset + flags_offset);
    }
    go_dynamic_span_prune(&state.goroutine, 0);
    const tp_info_t *previous = bpf_map_lookup_elem(&go_trace_map, &state.goroutine);
    if (previous) {
        state.previous = *previous;
    }
    go_addr_key_t span_key = {};
    go_addr_key_from_id(&span_key, span);
    if (bpf_map_update_elem(&dynamic_sdk_contexts, &span_key, &state, BPF_ANY)) {
        return 0;
    }
    bpf_map_update_elem(&go_trace_map, &state.goroutine, &state.current, BPF_ANY);
    obi_ctx__set(bpf_get_current_pid_tgid(), &state.current);
    return 0;
}

SEC("uprobe/sdk_recording_span_end")
int GUARDED_PROG(obi_uprobe_sdk_recording_span_end, struct pt_regs *, ctx) {
    go_addr_key_t span_key = {};
    go_addr_key_from_id(&span_key, GO_PARAM1(ctx));
    const struct dynamic_sdk_context *state = bpf_map_lookup_elem(&dynamic_sdk_contexts, &span_key);
    if (!state) {
        return 0;
    }
    const tp_info_t *current = bpf_map_lookup_elem(&go_trace_map, &state->goroutine);
    if (current &&
        !bpf_memcmp(current->span_id, state->current.span_id, sizeof(current->span_id))) {
        bpf_map_update_elem(&go_trace_map, &state->goroutine, &state->previous, BPF_ANY);
        if ((u64)GOROUTINE_PTR(ctx) == state->goroutine.addr) {
            obi_ctx__set(bpf_get_current_pid_tgid(), &state->previous);
        }
    }
    bpf_map_delete_elem(&dynamic_sdk_contexts, &span_key);
    return 0;
}
