/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"errors"
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/verifier/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: ariesmemstorage.NewProvider(),
			VDRI:          &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test failure", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: errors.New("error creating the store")},
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{
		VDRI:          &vdrmock.MockVDRegistry{},
		StoreProvider: ariesmemstorage.NewProvider(),
	})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 5, len(ops))
}
