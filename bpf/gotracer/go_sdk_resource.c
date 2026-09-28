// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <common/event_defs.h>
#include <common/pin_internal.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <gotracer/go_common.h>
#include <gotracer/types/otel_types.h>

// Go's 64-bit internal/abi.Type layout is shared by amd64 and arm64.
enum {
    k_go_type_kind_offset = 23,
    k_go_kind_mask = 31,
    k_go_kind_array = 17,
    k_sdk_resource_max_attributes = 128,
    k_sdk_service_string_size = 256,
    k_sdk_resource_retry_ns = 1000000000,
};

struct go_sdk_resource_key {
    u64 process_start;
    u64 resource;
    u32 pid;
    u32 _pad;
};

struct go_sdk_resource_event {
    u8 type;
    u8 _pad[3];
    pid_info pid;
    u64 timestamp;
    struct go_sdk_resource_key key;
    unsigned char service_name[k_sdk_service_string_size];
    unsigned char service_namespace[k_sdk_service_string_size];
};

// Retain the event layout for bpf2go.
const struct go_sdk_resource_event *unused_sdk_resource_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct go_sdk_resource_key);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_sdk_resources_seen SEC(".maps");

static __always_inline bool sdk_resource_string(unsigned char *dst, const go_string_t *str) {
    if (str->len <= 0 || str->len >= k_sdk_service_string_size) {
        return false;
    }
    const u32 len = (u32)str->len & (k_sdk_service_string_size - 1);
    if (bpf_probe_read_user(dst, len, str->str)) {
        dst[0] = '\0';
        return false;
    }
    dst[len] = '\0';
    return true;
}

SEC("uprobe/sdk_tracer_resource")
int GUARDED_PROG(obi_uprobe_sdk_tracer_resource, struct pt_regs *, ctx) {
    off_table_t *offsets = get_offsets_table();
    if (!offsets) {
        return 0;
    }
    const u64 provider_pos = go_offset_of(offsets, (go_offset){.v = _sdk_tracer_provider_pos});
    const u64 resource_pos = go_offset_of(offsets, (go_offset){.v = _sdk_provider_resource_pos});
    const u64 attrs_pos = go_offset_of(offsets, (go_offset){.v = _sdk_resource_attrs_pos});
    const u64 data_pos = go_offset_of(offsets, (go_offset){.v = _sdk_attribute_set_data_pos});
    if (provider_pos == (u64)-1 || resource_pos == (u64)-1 || attrs_pos == (u64)-1 ||
        data_pos == (u64)-1) {
        return 0;
    }

    unsigned char *provider = NULL;
    unsigned char *resource = NULL;
    if (bpf_probe_read_user(
            &provider, sizeof(provider), (unsigned char *)GO_PARAM1(ctx) + provider_pos) ||
        !provider || bpf_probe_read_user(&resource, sizeof(resource), provider + resource_pos) ||
        !resource) {
        return 0;
    }

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct go_sdk_resource_key key = {
        .process_start = BPF_CORE_READ(task, group_leader, start_time),
        .resource = (u64)resource,
        .pid = pid_from_pid_tgid(bpf_get_current_pid_tgid()),
    };
    const u64 now = bpf_ktime_get_ns();
    const u64 *seen = bpf_map_lookup_elem(&go_sdk_resources_seen, &key);
    if (seen && (*seen == (u64)-1 || now - *seen < k_sdk_resource_retry_ns)) {
        return 0;
    }

    go_iface_t attrs = {};
    u64 size = 0;
    u8 kind = 0;
    if (bpf_probe_read_user(&attrs, sizeof(attrs), resource + attrs_pos + data_pos) ||
        !attrs.type || !attrs.data || bpf_probe_read_user(&size, sizeof(size), attrs.type) ||
        bpf_probe_read_user(
            &kind, sizeof(kind), (unsigned char *)attrs.type + k_go_type_kind_offset) ||
        (kind & k_go_kind_mask) != k_go_kind_array || size % sizeof(go_otel_key_value_t)) {
        return 0;
    }

    struct go_sdk_resource_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    bpf_memset(event->_pad, 0, sizeof(event->_pad));
    bpf_memset(event->service_name, 0, sizeof(event->service_name));
    bpf_memset(event->service_namespace, 0, sizeof(event->service_namespace));
    event->type = k_event_type_go_sdk_resource;
    event->timestamp = now;
    event->key = key;
    task_pid(&event->pid);

    const u64 count = size / sizeof(go_otel_key_value_t);
    for (u32 i = 0; i < k_sdk_resource_max_attributes; i++) {
        if (i >= count) {
            break;
        }
        go_otel_key_value_t attr = {};
        if (bpf_probe_read_user(
                &attr, sizeof(attr), (unsigned char *)attrs.data + i * sizeof(attr))) {
            break;
        }
        if (attr.value.vtype != attr_type_string ||
            (attr.key.len != sizeof("service.name") - 1 &&
             attr.key.len != sizeof("service.namespace") - 1)) {
            continue;
        }
        unsigned char name[OTEL_ATTRIBUTE_KEY_MAX_LEN] = {};
        if (bpf_probe_read_user(name, attr.key.len & (sizeof(name) - 1), attr.key.str)) {
            continue;
        }
        if (attr.key.len == sizeof("service.name") - 1 &&
            !bpf_memcmp(name, "service.name", sizeof("service.name") - 1)) {
            sdk_resource_string(event->service_name, &attr.value.string);
        } else if (attr.key.len == sizeof("service.namespace") - 1 &&
                   !bpf_memcmp(name, "service.namespace", sizeof("service.namespace") - 1)) {
            sdk_resource_string(event->service_namespace, &attr.value.string);
        }
    }
    if (event->service_name[0] || event->service_namespace[0]) {
        // Retry until userspace acknowledges a tracked process; discovery may lag this uprobe.
        bpf_map_update_elem(&go_sdk_resources_seen, &key, &now, BPF_ANY);
        bpf_ringbuf_submit(event, get_flags());
    } else {
        const u64 acknowledged = (u64)-1;
        bpf_map_update_elem(&go_sdk_resources_seen, &key, &acknowledged, BPF_ANY);
        bpf_ringbuf_discard(event, 0);
    }
    return 0;
}
