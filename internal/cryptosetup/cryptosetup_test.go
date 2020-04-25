/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cryptosetup

import (
	"encoding/base64"
	"errors"
	"testing"

	kmsservice "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

var errTest = errors.New("testError")

func TestPrepareMasterKeyReader(t *testing.T) {
	t.Run("Unexpected error when trying to retrieve master key from store", func(t *testing.T) {
		reader, err := PrepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: errTest}})
		require.Equal(t, errTest, err)
		require.Nil(t, reader)
	})
	t.Run("Error when putting newly generated master key into store", func(t *testing.T) {
		reader, err := PrepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: storage.ErrDataNotFound,
					ErrPut: errTest}})
		require.Equal(t, errTest, err)
		require.Nil(t, reader)
	})
}

func TestPrepareJWECrypto(t *testing.T) {
	t.Run("Success: signing key store already contains a signing key", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(signingKeyDBKeyName, []byte("testKey"))
		require.NoError(t, err)

		signingKey, packer, err := PrepareJWECrypto(nil, mockStoreProvider)
		require.NoError(t, err)
		require.Equal(t, "testKey", signingKey)
		require.NotNil(t, packer)
	})
	t.Run("Failure: unexpected error while getting signing key from store", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()

		mockStoreProvider.Store.ErrGet = errTest
		err := mockStoreProvider.Store.Put(signingKeyDBKeyName, []byte("testKey"))
		require.NoError(t, err)

		signingKey, packer, err := PrepareJWECrypto(nil, mockStoreProvider)
		require.Equal(t, errTest, err)
		require.Empty(t, signingKey)
		require.Nil(t, packer)
	})
	t.Run("Failure while creating key set when no existing signing key found", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()

		mockKMS := legacykms.CloseableKMS{CreateKeyErr: errTest}

		signingKey, packer, err := PrepareJWECrypto(&mockKMS, mockStoreProvider)
		require.Equal(t, errTest, err)
		require.Empty(t, signingKey)
		require.Nil(t, packer)
	})
	t.Run("Failure while putting newly created signing key into signing key store", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		mockKMS := legacykms.CloseableKMS{}

		signingKey, packer, err := PrepareJWECrypto(&mockKMS, mockStoreProvider)
		require.Equal(t, errTest, err)
		require.Empty(t, signingKey)
		require.Nil(t, packer)
	})
}

func TestPrepareMACCrypto(t *testing.T) {
	t.Run("Success: key ID already in store", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(keyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)

		mockKMS := kms.KeyManager{}

		testMACValue := []byte("testValue")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, &mockCrypto)
		require.NoError(t, err)
		require.Nil(t, keySetHandle)
		require.Equal(t, base64.URLEncoding.EncodeToString(testMACValue), encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: key ID already in store, "+
		"but failed to retrieve key handle from key manager", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(keyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)

		mockKMS := kms.KeyManager{GetKeyErr: errTest}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, nil)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: key ID already in store, "+
		"but failed to assert retrieved key handle from key manager as a *keyset.Handle", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(keyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)

		mockKMS := mockKeyManager{}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, nil)
		require.Equal(t, errKeySetHandleAssertionFailure, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Unexpected failure while getting key ID from store", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(keyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)
		mockStoreProvider.Store.ErrGet = errTest

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(nil, mockStoreProvider, nil)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure while creating new HMAC key set", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()

		mockKMS := kms.KeyManager{CreateKeyErr: errTest}

		testMACValue := []byte("keyHandle")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, &mockCrypto)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: unable to assert newly created key handle as a *keyset.Handle", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		mockKMS := mockKeyManager{}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, nil)
		require.Equal(t, errKeySetHandleAssertionFailure, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: error while putting new key ID in store", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		mockKMS := kms.KeyManager{}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, nil)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure while computing MAC", func(t *testing.T) {
		mockStoreProvider := mockstore.NewMockStoreProvider()

		mockKMS := kms.KeyManager{}

		mockCrypto := crypto.Crypto{ComputeMACErr: errTest}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, &mockCrypto)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
}

type mockKeyManager struct {
}

func (m mockKeyManager) Create(kt kmsservice.KeyType) (string, interface{}, error) {
	return "", nil, nil
}

func (m mockKeyManager) Get(keyID string) (interface{}, error) {
	return nil, nil
}

func (m mockKeyManager) Rotate(kt kmsservice.KeyType, keyID string) (string, interface{}, error) {
	panic("implement me")
}
