/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
	"github.com/trustbloc/edge-service/pkg/internal/mock/kms"
	"github.com/trustbloc/edge-service/pkg/restapi/vc/operation"
)

func TestIssuerController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		controller, err := New(&operation.Config{StoreProvider: memstore.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "issuer"})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		controller, err := New(&operation.Config{StoreProvider: &mockstore.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")}, EDVClient: client,
			VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "issuer"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestVerifierController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		controller, err := New(&operation.Config{StoreProvider: memstore.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "verifier"})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		controller, err := New(&operation.Config{StoreProvider: &mockstore.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")}, EDVClient: client,
			VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "verifier"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, controller)
	})
}

func TestControllerInvalidMode_New(t *testing.T) {
	t.Run("must return error if an invalid mode is given", func(t *testing.T) {
		_, err := New(&operation.Config{StoreProvider: &mockstore.Provider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")},
			EDVClient: edv.NewMockEDVClient("test", nil, nil, []string{"testID"}),
			VDRI:      &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "invalid"})
		require.Error(t, err)
	})
}

func TestIssuerController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	controller, err := New(&operation.Config{StoreProvider: memstore.NewProvider(),
		Crypto:             &cryptomock.Crypto{},
		KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
		VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "issuer"})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 9, len(ops))
}

func TestVerifierController_GetOperations(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	controller, err := New(&operation.Config{StoreProvider: memstore.NewProvider(),
		Crypto:             &cryptomock.Crypto{},
		KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
		VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "", Mode: "verifier"})

	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 3, len(ops))
}
