// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <gotracer/go_common.h>
#include <shared/custom_span.c>

static __always_inline void go_custom_span_context(struct pt_regs *ctx,
                                                   const struct obi_usdt_spec *spec,
                                                   u8 kind,
                                                   struct custom_span_event *event) {
    if (spec->pair_kind != k_obi_usdt_pair_g) {
        return;
    }
    go_addr_key_t goroutine = {};
    go_addr_key_from_id(&goroutine, GOROUTINE_PTR(ctx));
    const u32 stack_off = go_obi_ctx__stack_off(ctx);
    if (kind == k_custom_span_kind_end) {
        go_dynamic_span_prune(&goroutine, 0);
        const u64 *head = bpf_map_lookup_elem(&go_dynamic_span_heads, &goroutine);
        if (!head) {
            return;
        }
        const struct go_dynamic_frame_key key = {.goroutine = goroutine, .id = *head};
        const struct go_dynamic_frame *frame = bpf_map_lookup_elem(&go_dynamic_span_frames, &key);
        if (frame && frame->cookie == spec->cookie && frame->stack_off == stack_off) {
            if (event) {
                bpf_memcpy(event->span_id, frame->current.span_id, sizeof(event->span_id));
            }
            go_dynamic_restore(&goroutine, frame);
            bpf_map_delete_elem(&go_dynamic_span_frames, &key);
            go_dynamic_span_prune(&goroutine, 0);
        }
        return;
    }
    if (!event) {
        return;
    }
    go_dynamic_span_prune(&goroutine, stack_off);
    struct go_dynamic_frame *frame = go_dynamic_frame_scratch_mem();
    if (!frame) {
        return;
    }
    bpf_memset(frame, 0, sizeof(*frame));
    frame->cookie = spec->cookie;
    frame->stack_off = stack_off;
    if (has_attach_cookie) {
        frame->spec_id = (u32)bpf_get_attach_cookie(ctx);
    }
    const u64 *head = bpf_map_lookup_elem(&go_dynamic_span_heads, &goroutine);
    if (head) {
        frame->parent = *head;
    }
    const tp_info_t *previous = bpf_map_lookup_elem(&go_trace_map, &goroutine);
    if (previous) {
        frame->previous = *previous;
    }
    const tp_info_t *parent = tp_info_from_parent_go(&goroutine, NULL);
    frame->current.ts = event->timestamp;
    frame->current.flags = k_flag_sampled;
    if (go_dynamic_valid_context(parent)) {
        tp_from_parent(&frame->current, parent);
    } else {
        urand_bytes(frame->current.trace_id, sizeof(frame->current.trace_id));
    }
    urand_bytes(frame->current.span_id, sizeof(frame->current.span_id));
    if (kind == k_custom_span_kind_start && !go_dynamic_span_push(&goroutine, frame)) {
        return;
    }
    bpf_memcpy(
        event->trace_ctx.trace_id, frame->current.trace_id, sizeof(event->trace_ctx.trace_id));
    bpf_memcpy(
        event->trace_ctx.span_id, frame->current.parent_id, sizeof(event->trace_ctx.span_id));
    bpf_memcpy(event->span_id, frame->current.span_id, sizeof(event->span_id));
    event->has_trace_ctx = *(const u64 *)frame->current.parent_id != 0;
    event->trace_flags = frame->current.flags;
}

SEC("uprobe/obi_custom_span_start")
int GUARDED_PROG(obi_custom_span_start, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_start, go_custom_span_context);
}

SEC("uprobe/obi_custom_span_end")
int GUARDED_PROG(obi_custom_span_end, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_end, go_custom_span_context);
}

SEC("uprobe/obi_custom_span_event")
int GUARDED_PROG(obi_custom_span_event, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_single, go_custom_span_context);
}

SEC("uretprobe/obi_custom_span_func_ret")
int GUARDED_PROG(obi_custom_span_func_ret, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_end, go_custom_span_context);
}
