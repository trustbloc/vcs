/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := operation.New(nil)
		require.NoError(t, err)
		require.NotNil(t, controller)

		require.Equal(t, 0, len(controller.GetRESTHandlers()))
	})
}
