// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <shared/custom_span.c>

SEC("uprobe/obi_custom_span_start")
int GUARDED_PROG(obi_custom_span_start, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_start, NULL);
}

SEC("uprobe/obi_custom_span_end")
int GUARDED_PROG(obi_custom_span_end, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_end, NULL);
}

SEC("uprobe/obi_custom_span_event")
int GUARDED_PROG(obi_custom_span_event, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_single, NULL);
}

SEC("uretprobe/obi_custom_span_func_ret")
int GUARDED_PROG(obi_custom_span_func_ret, struct pt_regs *, ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_end, NULL);
}
