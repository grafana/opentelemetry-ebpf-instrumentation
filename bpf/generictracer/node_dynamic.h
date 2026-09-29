// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/common.h>
#include <common/event_defs.h>
#include <common/ringbuf.h>
#include <pid/pid.h>
#include <shared/obi_ctx.h>
#include <generictracer/nodejs_helpers.h>
#include <common/maps/dynamic_invocations.h>
#include <maps/node_dynamic_spans.h>

enum {
    k_node_dynamic_op_offset = sizeof("/dev/null/obi-dy/") - 1,
    k_node_dynamic_payload_offset = k_node_dynamic_op_offset + 1,
    k_node_dynamic_key_hex_len = 32,
    k_node_dynamic_start_len = 100,
    k_node_dynamic_ready_len = 65,
};

struct node_dynamic_ready {
    u8 type;
    u8 padding[3];
    u32 pid;
    u32 port;
    u32 reserved;
    unsigned char token[16];
    u64 revision;
};

static __always_inline int node_dynamic_digit(unsigned char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static __always_inline bool
node_dynamic_hex(const unsigned char *src, unsigned char *dest, u32 size) {
    for (u32 i = 0; i < size; i++) {
        const int high = node_dynamic_digit(src[i * 2]);
        const int low = node_dynamic_digit(src[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        dest[i] = (high << 4) | low;
    }
    return true;
}

static __always_inline void node_dynamic_ready_event(const char *path, u64 pid_tgid) {
    unsigned char payload[k_node_dynamic_ready_len];
    u64 port = 0;
    if (bpf_probe_read_user(payload, sizeof(payload), path + k_node_dynamic_payload_offset) ||
        payload[sizeof(payload) - 1] != '\0' || nodejs_parse_hex_u64(payload, &port) || !port ||
        port > 65535) {
        return;
    }
    struct node_dynamic_ready *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    bpf_memset(event, 0, sizeof(*event));
    event->type = k_event_type_node_dynamic_ready;
    event->pid = pid_from_pid_tgid(pid_tgid);
    event->port = port;
    if (!node_dynamic_hex(payload + 16, event->token, sizeof(event->token)) ||
        nodejs_parse_hex_u64(payload + 48, &event->revision)) {
        bpf_ringbuf_discard(event, 0);
        return;
    }
    bpf_ringbuf_submit(event, get_flags());
}

static __always_inline void
node_dynamic_start(const char *path, u64 pid_tgid, const struct node_dynamic_key *key, u64 cookie) {
    unsigned char payload[k_node_dynamic_start_len];
    if (bpf_probe_read_user(payload, sizeof(payload), path + k_node_dynamic_payload_offset) ||
        payload[sizeof(payload) - 1] != '\0') {
        return;
    }
    struct node_dynamic_context context = {.cookie = cookie};
    tp_info_t *tp = &context.trace.tp;
    if (!node_dynamic_hex(payload + 32, tp->trace_id, sizeof(tp->trace_id)) ||
        !node_dynamic_hex(payload + 64, tp->span_id, sizeof(tp->span_id)) ||
        !node_dynamic_hex(payload + 80, tp->parent_id, sizeof(tp->parent_id)) ||
        !node_dynamic_hex(payload + 96, &tp->flags, sizeof(tp->flags))) {
        return;
    }
    if (payload[98] == '1') {
        const tp_info_pid_t *parent = node_dynamic_parent(pid_tgid);
        if (parent) {
            bpf_memcpy(tp->trace_id, parent->tp.trace_id, sizeof(tp->trace_id));
            bpf_memcpy(tp->parent_id, parent->tp.span_id, sizeof(tp->parent_id));
            tp->flags = parent->tp.flags;
        } else {
            const tp_info_t *ctx = bpf_map_lookup_elem(&node_dynamic_requests, &pid_tgid);
            if (ctx) {
                bpf_memcpy(tp->trace_id, (void *)ctx->trace_id, sizeof(tp->trace_id));
                bpf_memcpy(tp->parent_id, (void *)ctx->span_id, sizeof(tp->parent_id));
                tp->flags = ctx->flags;
            }
        }
    }
    tp->ts = bpf_ktime_get_ns();
    context.trace.pid = key->pid;
    context.trace.valid = 1;
    u64 *count = bpf_map_lookup_elem(&obi_dynamic_invocations, &cookie);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    if (!bpf_map_update_elem(&node_dynamic_calls, key, &context, BPF_NOEXIST)) {
        bpf_map_update_elem(&node_dynamic_active, &pid_tgid, key, BPF_ANY);
    }
}

static __always_inline void node_dynamic_end(const char *path,
                                             const struct node_dynamic_key *key,
                                             const struct node_dynamic_context *context) {
    node_dynamic_span_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->cookie = context->cookie;
        node_span_event_t *span = &event->span;
        span->type = k_event_type_node_dynamic_span;
        span->has_parent_ctx = 1;
        event->trace_flags = context->trace.tp.flags;
        span->end_ktime = bpf_ktime_get_ns();
        task_pid(&span->pid);
        bpf_memcpy(
            span->parent_trace_id, context->trace.tp.trace_id, sizeof(span->parent_trace_id));
        bpf_memcpy(span->parent_span_id, context->trace.tp.parent_id, sizeof(span->parent_span_id));
        const long length = bpf_probe_read_user_str(span->payload,
                                                    sizeof(span->payload),
                                                    path + k_node_dynamic_payload_offset +
                                                        k_node_dynamic_key_hex_len);
        if (length > 1 && length < sizeof(span->payload)) {
            span->payload_len = length - 1;
            bpf_ringbuf_submit(event, get_flags());
        } else {
            bpf_ringbuf_discard(event, 0);
        }
    }
    bpf_map_delete_elem(&node_dynamic_calls, key);
}

static __always_inline int handle_node_dynamic(const char *path, u64 pid_tgid, unsigned char op) {
    if (op == 'r') {
        node_dynamic_ready_event(path, pid_tgid);
        return 0;
    }
    unsigned char payload[k_node_dynamic_key_hex_len];
    struct node_dynamic_key key = {.pid = pid_from_pid_tgid(pid_tgid)};
    u64 cookie = 0;
    if (bpf_probe_read_user(payload, sizeof(payload), path + k_node_dynamic_payload_offset) ||
        nodejs_parse_hex_u64(payload, &cookie) ||
        nodejs_parse_hex_u64(payload + 16, &key.invocation)) {
        return 0;
    }
    if (op == 'c' && !cookie && !key.invocation) {
        bpf_map_delete_elem(&node_dynamic_active, &pid_tgid);
        return 0;
    }
    const u32 *allowed = bpf_map_lookup_elem(&obi_node_dynamic_probes, &cookie);
    if (!allowed || *allowed != key.pid) {
        if (op == 'c') {
            bpf_map_delete_elem(&node_dynamic_active, &pid_tgid);
        }
        return 0;
    }
    if (op == 's') {
        node_dynamic_start(path, pid_tgid, &key, cookie);
        return 0;
    }
    const struct node_dynamic_context *context = bpf_map_lookup_elem(&node_dynamic_calls, &key);
    if (!context || context->cookie != cookie) {
        if (op == 'c') {
            bpf_map_delete_elem(&node_dynamic_active, &pid_tgid);
        }
        return 0;
    }
    if (op == 'c') {
        bpf_map_update_elem(&node_dynamic_active, &pid_tgid, &key, BPF_ANY);
    } else if (op == 'e') {
        node_dynamic_end(path, &key, context);
    }
    return 0;
}
