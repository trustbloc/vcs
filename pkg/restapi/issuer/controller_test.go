/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"fmt"
	"testing"

	"github.com/trustbloc/vcs/pkg/storage/ariesprovider"

	"github.com/google/tink/go/keyset"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/restapi/issuer/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
		require.NoError(t, err)

		controller, err := New(&operation.Config{
			StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
			Crypto:        &cryptomock.Crypto{},
			KeyManager:    &mockkms.KeyManager{CreateKeyValue: kh},
			VDRI:          &vdrmock.MockVDRegistry{}, HostURL: "",
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		controller, err := New(&operation.Config{
			StoreProvider: ariesprovider.New(&ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error open store"),
			}),
			VDRI: &vdrmock.MockVDRegistry{}, HostURL: "",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	controller, err := New(&operation.Config{
		StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
		Crypto:        &cryptomock.Crypto{},
		KeyManager:    &mockkms.KeyManager{CreateKeyValue: kh},
		VDRI:          &vdrmock.MockVDRegistry{}, HostURL: "",
	})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 10, len(ops))
}
