// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/maps/dynamic_invocations.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>
#include <common/trace_parent.h>
#include <shared/custom_span.h>

enum {
    k_ioctl_java_dynamic_task_capture = 11,
    k_ioctl_java_dynamic_task_enter = 12,
    k_ioctl_java_dynamic_task_exit = 13,
    k_ioctl_java_dynamic_task_cancel = 14,
};

struct java_dynamic_packet {
    u8 operation;
    u8 flags;
    u8 arg_count;
    u8 adopt_parent;
    u16 value_mask;
    u8 padding[2];
    u64 cookie;
    u64 invocation;
    u64 thread;
    unsigned char trace_id[16];
    unsigned char parent_id[8];
    unsigned char span_id[8];
    u64 previous_cookie;
    unsigned char previous_trace_id[16];
    unsigned char previous_parent_id[8];
    unsigned char previous_span_id[8];
    u8 previous_flags;
    u8 previous_padding[7];
    unsigned char args[k_custom_span_max_args][k_custom_span_str_len];
};

struct java_dynamic_ready {
    u8 type;
    u8 padding[3];
    u32 pid;
    u32 port;
    u32 reserved;
    unsigned char token[16];
    u64 revision;
};

SCRATCH_MEM_TYPED(java_dynamic_packet, struct java_dynamic_packet);

static __always_inline void java_dynamic_task_op(const u8 op, const unsigned char *user, u64 id) {
    u64 task_id = 0;
    if (bpf_probe_read_user(&task_id, sizeof(task_id), user + 1) != 0) {
        return;
    }
    struct java_dynamic_task_key task_key = {
        .pid = pid_from_pid_tgid(id),
        .task_id = task_id,
    };
    if (op == k_ioctl_java_dynamic_task_cancel) {
        bpf_map_delete_elem(&java_dynamic_task_contexts, &task_key);
        return;
    }
    if (op == k_ioctl_java_dynamic_task_capture) {
        trace_key_t key = {};
        trace_key_from_pid_tid(&key);
        struct java_dynamic_context *current = bpf_map_lookup_elem(&java_dynamic_spans, &key);
        if (current) {
            bpf_map_update_elem(&java_dynamic_task_contexts, &task_key, current, BPF_ANY);
        } else {
            bpf_map_delete_elem(&java_dynamic_task_contexts, &task_key);
        }
        return;
    }

    if (op == k_ioctl_java_dynamic_task_enter) {
        struct java_dynamic_task_scope_state *scopes =
            bpf_map_lookup_elem(&java_dynamic_task_scopes, &id);
        if (!scopes) {
            struct java_dynamic_task_scope_state empty = {};
            if (bpf_map_update_elem(&java_dynamic_task_scopes, &id, &empty, BPF_NOEXIST) != 0) {
                return;
            }
            scopes = bpf_map_lookup_elem(&java_dynamic_task_scopes, &id);
            if (!scopes) {
                return;
            }
        }
        if (scopes->overflow_depth > 0 || scopes->depth >= k_java_dynamic_task_scope_max_depth) {
            scopes->overflow_depth++;
            return;
        }

        trace_key_t key = {};
        trace_key_from_pid_tid(&key);
        struct java_dynamic_task_scope_key scope_key = {.pid_tgid = id, .depth = scopes->depth};
        struct java_dynamic_task_scope_frame frame = {};
        struct java_dynamic_context *previous = bpf_map_lookup_elem(&java_dynamic_spans, &key);
        if (previous) {
            frame.had_previous = 1;
            frame.previous = *previous;
        }
        struct java_dynamic_context *captured =
            bpf_map_lookup_elem(&java_dynamic_task_contexts, &task_key);
        frame.captured = captured != NULL;
        if (bpf_map_update_elem(&java_dynamic_task_backups, &scope_key, &frame, BPF_ANY) != 0) {
            scopes->depth++;
            return;
        }
        if (captured) {
            bpf_map_update_elem(&java_dynamic_spans, &key, captured, BPF_ANY);
        }
        scopes->depth++;
        bpf_map_delete_elem(&java_dynamic_task_contexts, &task_key);
        return;
    }

    struct java_dynamic_task_scope_state *scopes =
        bpf_map_lookup_elem(&java_dynamic_task_scopes, &id);
    if (scopes) {
        if (scopes->overflow_depth > 0) {
            scopes->overflow_depth--;
        } else if (scopes->depth > 0) {
            struct java_dynamic_task_scope_key scope_key = {.pid_tgid = id,
                                                            .depth = scopes->depth - 1};
            struct java_dynamic_task_scope_frame *frame =
                bpf_map_lookup_elem(&java_dynamic_task_backups, &scope_key);
            if (frame) {
                if (frame->had_previous) {
                    trace_key_t key = {};
                    trace_key_from_pid_tid(&key);
                    bpf_map_update_elem(&java_dynamic_spans, &key, &frame->previous, BPF_ANY);
                } else if (frame->captured) {
                    trace_key_t key = {};
                    trace_key_from_pid_tid(&key);
                    bpf_map_delete_elem(&java_dynamic_spans, &key);
                }
            }
            bpf_map_delete_elem(&java_dynamic_task_backups, &scope_key);
            scopes->depth--;
        }
        if (scopes->depth == 0 && scopes->overflow_depth == 0) {
            bpf_map_delete_elem(&java_dynamic_task_scopes, &id);
        }
    }
    bpf_map_delete_elem(&java_dynamic_task_contexts, &task_key);
}

static __always_inline void java_dynamic_ready_event(const unsigned char *packet, u64 pid_tgid) {
    struct java_dynamic_ready *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    bpf_memset(event, 0, sizeof(*event));
    event->type = k_event_type_java_dynamic_ready;
    event->pid = pid_from_pid_tgid(pid_tgid);
    if (bpf_probe_read_user(&event->port, sizeof(event->port), packet + 4) ||
        bpf_probe_read_user(event->token, sizeof(event->token), packet + 8) ||
        bpf_probe_read_user(&event->revision, sizeof(event->revision), packet + 24)) {
        bpf_ringbuf_discard(event, 0);
        return;
    }
    bpf_ringbuf_submit(event, get_flags());
}

static __always_inline void java_dynamic_span_event(unsigned char *user, u64 pid_tgid, bool start) {
    struct java_dynamic_packet *packet = java_dynamic_packet_mem();
    if (!packet || bpf_probe_read_user(packet, sizeof(*packet), user)) {
        return;
    }
    const u32 *allowed_pid = bpf_map_lookup_elem(&obi_java_dynamic_probes, &packet->cookie);
    const bool active = allowed_pid && *allowed_pid == pid_from_pid_tgid(pid_tgid);
    trace_key_t key = {};
    trace_key_from_pid_tid(&key);

    if (start) {
        if (!active) {
            return;
        }
        u64 *count = bpf_map_lookup_elem(&obi_dynamic_invocations, &packet->cookie);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        if (packet->adopt_parent && g_bpf_probe_write_user_enabled) {
            trace_key_t parent_key = key;
            const tp_info_pid_t *parent = find_parent_java_trace(&parent_key);
            if (parent && parent->valid) {
                bpf_memcpy(packet->trace_id, parent->tp.trace_id, sizeof(packet->trace_id));
                bpf_memcpy(packet->parent_id, parent->tp.span_id, sizeof(packet->parent_id));
                packet->flags = parent->tp.flags;
                bpf_probe_write_user(user + offsetof(struct java_dynamic_packet, trace_id),
                                     packet->trace_id,
                                     sizeof(packet->trace_id) + sizeof(packet->parent_id));
                bpf_probe_write_user(user + offsetof(struct java_dynamic_packet, flags),
                                     &packet->flags,
                                     sizeof(packet->flags));
            }
        }
        if (bpf_probe_read_user(packet->trace_id,
                                sizeof(packet->trace_id) + sizeof(packet->parent_id),
                                user + offsetof(struct java_dynamic_packet, trace_id)) ||
            bpf_probe_read_user(&packet->flags,
                                sizeof(packet->flags),
                                user + offsetof(struct java_dynamic_packet, flags))) {
            return;
        }
        struct java_dynamic_context context = {.cookie = packet->cookie};
        bpf_memcpy(context.trace.tp.trace_id, packet->trace_id, sizeof(packet->trace_id));
        bpf_memcpy(context.trace.tp.span_id, packet->span_id, sizeof(packet->span_id));
        bpf_memcpy(context.trace.tp.parent_id, packet->parent_id, sizeof(packet->parent_id));
        context.trace.tp.flags = packet->flags;
        context.trace.tp.ts = bpf_ktime_get_ns();
        context.trace.pid = pid_from_pid_tgid(pid_tgid);
        context.trace.valid = 1;
        bpf_map_update_elem(&java_dynamic_spans, &key, &context, BPF_ANY);
    } else {
        struct java_dynamic_context *current = bpf_map_lookup_elem(&java_dynamic_spans, &key);
        if (current && current->cookie == packet->cookie &&
            bpf_memcmp(current->trace.tp.span_id, packet->span_id, sizeof(packet->span_id)) == 0) {
            if (packet->previous_cookie &&
                bpf_map_lookup_elem(&obi_java_dynamic_probes, &packet->previous_cookie)) {
                current->cookie = packet->previous_cookie;
                bpf_memcpy(current->trace.tp.trace_id,
                           packet->previous_trace_id,
                           sizeof(packet->previous_trace_id));
                bpf_memcpy(current->trace.tp.parent_id,
                           packet->previous_parent_id,
                           sizeof(packet->previous_parent_id));
                bpf_memcpy(current->trace.tp.span_id,
                           packet->previous_span_id,
                           sizeof(packet->previous_span_id));
                current->trace.tp.flags = packet->previous_flags;
            } else {
                bpf_map_delete_elem(&java_dynamic_spans, &key);
            }
        }
        if (!active) {
            return;
        }
    }

    struct custom_span_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    bpf_memset(event, 0, offsetof(struct custom_span_event, arg_str));
    bpf_probe_read_kernel(event->arg_str, sizeof(event->arg_str), packet->args);
    event->type = k_event_type_custom_span;
    event->kind = start ? k_custom_span_kind_start : k_custom_span_kind_end;
    event->pair_kind = k_obi_usdt_pair_java;
    event->g_ptr = packet->invocation;
    event->cookie = packet->cookie;
    event->timestamp = bpf_ktime_get_ns();
    event->global_pid = pid_from_pid_tgid(pid_tgid);
    event->global_tid = tid_from_pid_tgid(pid_tgid);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    ns_pid_ppid(task, &ns_pid, &ns_ppid, &event->pid_ns_id);
    event->ns_pid = (u32)ns_pid;
    event->ns_tid = get_task_tid();
    event->has_trace_ctx = 1;
    event->trace_flags = packet->flags;
    bpf_memcpy(event->trace_ctx.trace_id, packet->trace_id, sizeof(packet->trace_id));
    bpf_memcpy(event->trace_ctx.span_id, packet->parent_id, sizeof(packet->parent_id));
    bpf_memcpy(event->span_id, packet->span_id, sizeof(packet->span_id));
    event->arg_cnt = packet->arg_count;
    for (u32 i = 0; i < k_custom_span_max_args; ++i) {
        if (i < packet->arg_count && (packet->value_mask & (1U << i))) {
            event->arg_kind[i] = k_custom_span_arg_str;
        }
    }
    bpf_ringbuf_submit(event, get_flags());
}
