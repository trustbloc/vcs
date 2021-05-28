/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package governance

import (
	"fmt"
	"testing"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/governance/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: ariesmemstorage.NewProvider(),
			Crypto:        &cryptomock.Crypto{}, VDRI: &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error open store"),
			},
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{
		StoreProvider: ariesmemstorage.NewProvider(),
		Crypto:        &cryptomock.Crypto{}, VDRI: &vdrmock.MockVDRegistry{},
	})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 3, len(ops))
}
