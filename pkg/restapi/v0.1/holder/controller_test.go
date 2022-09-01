/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"fmt"
	"testing"

	"github.com/trustbloc/vcs/pkg/restapi/v0.1/holder/operation"

	"github.com/trustbloc/vcs/pkg/storage/ariesprovider"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
			Crypto:        &cryptomock.Crypto{}, VDRI: &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: ariesprovider.New(&ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error open store"),
			}),
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{
		StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
		Crypto:        &cryptomock.Crypto{}, VDRI: &vdrmock.MockVDRegistry{},
	})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 5, len(ops))
}
