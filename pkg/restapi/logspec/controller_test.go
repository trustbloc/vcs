/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logspec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	t.Run("create new controller", func(t *testing.T) {
		controller := New()
		require.NotNil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	ops := New().GetOperations()
	require.Equal(t, 2, len(ops))
}
