/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"errors"
	"testing"

	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: memstore.NewProvider(),
			VDRI:          &vdrimock.MockVDRIRegistry{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test failure", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &mockstorage.Provider{ErrCreateStore: errors.New("error creating the store")},
			VDRI:          &vdrimock.MockVDRIRegistry{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{
		VDRI:          &vdrimock.MockVDRIRegistry{},
		StoreProvider: memstore.NewProvider(),
	})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 5, len(ops))
}
