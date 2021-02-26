/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
	"github.com/trustbloc/edge-service/pkg/restapi/issuer/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
		require.NoError(t, err)

		controller, err := New(&operation.Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: ariesmemstorage.NewProvider(), EDVClient: client,
			KeyManager: &mockkms.KeyManager{CreateKeyValue: kh},
			VDRI:       &vdrmock.MockVDRegistry{}, HostURL: "",
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
		controller, err := New(&operation.Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error open store"),
			}, EDVClient: client,
			VDRI: &vdrmock.MockVDRegistry{}, HostURL: "",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

	kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	controller, err := New(&operation.Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		Crypto:             &cryptomock.Crypto{},
		KMSSecretsProvider: ariesmemstorage.NewProvider(), EDVClient: client,
		KeyManager: &mockkms.KeyManager{CreateKeyValue: kh},
		VDRI:       &vdrmock.MockVDRegistry{}, HostURL: "",
	})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 10, len(ops))
}
