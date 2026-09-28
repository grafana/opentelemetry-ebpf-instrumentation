// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDynamicSpecsRecycleWithoutOverwritingResidentSpecs(t *testing.T) {
	var manager USDTSpecManager
	resident, err := manager.ID("jvm", 3)
	require.NoError(t, err)
	require.NotZero(t, resident)
	for index := range 1000 {
		key := strconv.Itoa(index)
		dynamic, err := manager.ID(key, 3)
		require.NoError(t, err)
		require.NotEqual(t, resident, dynamic)
		_, err = manager.ID("overflow", 3)
		require.Error(t, err)
		manager.Release(key)
		manager.Release(key)
	}
	same, err := manager.ID("jvm", 3)
	require.NoError(t, err)
	require.Equal(t, resident, same)
}
