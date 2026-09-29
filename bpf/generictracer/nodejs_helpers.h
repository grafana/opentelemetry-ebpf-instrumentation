// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static __always_inline int nodejs_parse_hex_u64(const unsigned char *buf, u64 *out) {
    u64 v = 0;
    for (u8 i = 0; i < sizeof(*out) * 2; ++i) {
        const unsigned char c = buf[i];
        u8 digit;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else {
            return -1;
        }
        v = (v << 4) | digit;
    }
    *out = v;
    return 0;
}
