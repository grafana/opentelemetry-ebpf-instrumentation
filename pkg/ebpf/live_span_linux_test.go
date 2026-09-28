// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func TestLiveSpecKeyUsesGenerationCookie(t *testing.T) {
	keys := map[string]bool{}
	for _, cookie := range []uint64{1, 2, 3} {
		target := usdtTarget{SpecKey: "EM_AARCH64:off:1f37d0", Spec: obiUSDTSpec{}}
		probe := &ebpfcommon.USDTProbeDesc{
			Cookie:      cookie,
			RewriteSpec: func(value any) (any, error) { return value, nil },
		}
		if _, err := applyUSDTRewrite(probe, &target); err != nil {
			t.Fatal(err)
		}
		if keys[target.SpecKey] {
			t.Fatalf("cookie %d reused spec key %q", cookie, target.SpecKey)
		}
		keys[target.SpecKey] = true
	}
}
