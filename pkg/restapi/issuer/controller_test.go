/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
	"github.com/trustbloc/edge-service/pkg/restapi/issuer/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		controller, err := New(&operation.Config{StoreProvider: memstore.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &mockkms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: ""})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
		controller, err := New(&operation.Config{StoreProvider: &mockstore.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")}, EDVClient: client,
			VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: ""})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	controller, err := New(&operation.Config{StoreProvider: memstore.NewProvider(),
		Crypto:             &cryptomock.Crypto{},
		KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &mockkms.KeyManager{CreateKeyValue: kh},
		VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: ""})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 10, len(ops))
}
