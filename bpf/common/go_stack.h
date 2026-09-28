// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

enum { k_g_stack_hi_off = 8 }; // runtime.g.stack.hi

// How deep the probed call is in the goroutine stack. When Go grows the stack it
// restarts the function, so the entry probe fires twice at the same depth. A nested
// call of the same kind is always deeper
static __always_inline u32 go_obi_ctx__stack_off(struct pt_regs *ctx) {
    u64 stack_hi = 0;
    bpf_probe_read_user(&stack_hi,
                        sizeof(stack_hi),
                        (void *)((unsigned char *)GOROUTINE_PTR(ctx) + k_g_stack_hi_off));
    return (u32)(stack_hi - PT_REGS_SP(ctx));
}
