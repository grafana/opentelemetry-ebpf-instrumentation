// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
)

func TestDWARFArgumentAndReturnRecipes(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(source, []byte(`package main
import "fmt"
//go:noinline
func capture(s string, count int32, flag bool) (string, int64) { if flag { return s, int64(count) }; return "", 0 }
func main() { fmt.Println(capture("hello", 7, true)) }
`), 0o600))
	binary := filepath.Join(dir, "fixture")
	command := exec.Command("go", "build", "-o", binary, source)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	ef, err := elf.Open(binary)
	require.NoError(t, err)
	defer ef.Close()
	spec, slots, err := BuildFunctionDWARFSpec(ef, &config.CustomSpanSpec{On: config.CustomSpanTarget{FunctionSpan: "main.capture"}}, 42, "amd64")
	require.NoError(t, err)
	require.Equal(t, uint16(3), spec.Spec.ArgCount)
	require.Equal(t, uint16(2), spec.Spec.ReturnArgCount)
	require.Equal(t, obiUSDTArgGoString, spec.Spec.Args[0].ArgType)
	require.Equal(t, uint8(32), spec.Spec.Args[1].ArgBitshift)
	require.Equal(t, uint8(1), spec.Spec.Args[1].ArgSigned)
	require.Equal(t, []AutoAttrSlot{
		{ArgIdx: 0, Name: "arg0", Type: config.CustomSpanAttrString},
		{ArgIdx: 1, Name: "arg1", Type: config.CustomSpanAttrI32},
		{ArgIdx: 2, Name: "arg2", Type: config.CustomSpanAttrU8},
		{Return: true, ArgIdx: 0, Name: "return0", Type: config.CustomSpanAttrString},
		{Return: true, ArgIdx: 1, Name: "return1", Type: config.CustomSpanAttrI64},
	}, slots)
}
