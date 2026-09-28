// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/event_defs.h>
#include <common/ringbuf.h>
#include <gotracer/go_common.h>
#include <shared/obi_ctx.h>

volatile const bool g_dynamic_goroutines_enabled = false;

enum go_dynamic_goroutine_kind {
    k_go_dynamic_goroutine_start = 1,
    k_go_dynamic_goroutine_end = 2,
};

struct go_dynamic_goroutine_event {
    u8 type;
    u8 kind;
    u8 _pad[2];
    u32 pid;
    u64 goroutine;
    u64 parent;
    obi_ctx_info_t trace_ctx;
};

static __always_inline void go_dynamic_goroutine_event(const go_addr_key_t *goroutine,
                                                       const go_addr_key_t *parent) {
    if (!g_dynamic_goroutines_enabled) {
        return;
    }

    if (parent && parent->addr != goroutine->addr) {
        go_dynamic_span_inherit(goroutine, parent);
    } else {
        go_dynamic_span_exit(goroutine);
    }

    struct go_dynamic_goroutine_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->type = k_event_type_go_dynamic_goroutine;
    event->kind = parent ? k_go_dynamic_goroutine_start : k_go_dynamic_goroutine_end;
    event->pid = goroutine->pid;
    event->goroutine = goroutine->addr;
    event->parent = parent ? parent->addr : 0;
    bpf_memset(event->_pad, 0, sizeof(event->_pad));
    bpf_memset(&event->trace_ctx, 0, sizeof(event->trace_ctx));
    if (parent) {
        const tp_info_t *context = bpf_map_lookup_elem(&go_trace_map, parent);
        if (context) {
            bpf_memcpy(event->trace_ctx.trace_id, context->trace_id, sizeof(context->trace_id));
            bpf_memcpy(event->trace_ctx.span_id, context->span_id, sizeof(context->span_id));
        }
    }
    bpf_ringbuf_submit(event, get_flags());
}
