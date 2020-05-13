/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"testing"

	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller := New(&operation.Config{
			VDRI: &vdrimock.MockVDRIRegistry{}})
		require.NotNil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller := New(&operation.Config{
		VDRI: &vdrimock.MockVDRIRegistry{}})
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 2, len(ops))
}
