/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comparator_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := comparator.New(nil)
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := comparator.New(nil)
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 0, len(ops))
}
