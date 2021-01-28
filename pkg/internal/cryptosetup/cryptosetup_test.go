/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cryptosetup

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	kmsservice "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"
)

var errTest = errors.New("testError")

func TestPrepareJWECrypto(t *testing.T) {
	t.Run("Fail to create JWE Encrypter", func(t *testing.T) {
		// Calling keyHandle.Public() on an HMAC key set isn't valid, which will cause PrepareJWECrypto to fail
		keyHandleToBeCreated, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)

		testMACValue := []byte("testValue")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		jweEncrypter, jweDecrypter, err := PrepareJWECrypto(&mockkms.KeyManager{CreateKeyValue: keyHandleToBeCreated},
			ariesmockstorage.NewMockStoreProvider(), &mockCrypto, jose.A256GCM, kmsservice.NISTP256ECDHKWType)
		require.EqualError(t, err, "keyset.Handle: keyset.Handle: keyset contains a non-private key")
		require.Nil(t, jweEncrypter)
		require.Nil(t, jweDecrypter)
	})
}

func Test_createJWEEncrypter(t *testing.T) {
	t.Run("Fail to unmarshal", func(t *testing.T) {
		keyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
		require.NoError(t, err)

		testMACValue := []byte("testValue")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		jweEncrypter, err := createJWEEncrypter("", keyHandle, jose.A256GCM, jose.DIDCommEncType,
			func(_ []byte, _ interface{}) error {
				return errTest
			}, nil, &mockCrypto)
		require.Equal(t, errTest, err)
		require.Nil(t, jweEncrypter)
	})
	t.Run("Fail to create new JWE Encrypter", func(t *testing.T) {
		keyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
		require.NoError(t, err)

		testMACValue := []byte("testValue")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		jweEncrypter, err := createJWEEncrypter("", keyHandle, jose.A256GCM, jose.DIDCommEncType, json.Unmarshal,
			func(alg jose.EncAlg, encType, senderKID string, senderKH *keyset.Handle,
				keys []*cryptoapi.PublicKey, crypto cryptoapi.Crypto) (*jose.JWEEncrypt, error) {
				return nil, errTest
			}, &mockCrypto)
		require.Equal(t, errTest, err)
		require.Nil(t, jweEncrypter)
	})
}

func TestPrepareMACCrypto(t *testing.T) {
	t.Run("Success: key ID already in store", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(hmacKeyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)

		mockKMS := mockkms.KeyManager{}

		testMACValue := []byte("testValue")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, &mockCrypto,
			kmsservice.HMACSHA256Tag256Type)
		require.NoError(t, err)
		require.Nil(t, keySetHandle)
		require.Equal(t, base64.URLEncoding.EncodeToString(testMACValue), encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: key ID already in store, "+
		"but failed to retrieve key handle from key manager", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(hmacKeyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)

		mockKMS := mockkms.KeyManager{GetKeyErr: errTest}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, nil,
			kmsservice.HMACSHA256Tag256Type)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: key ID already in store, "+
		"but failed to assert retrieved key handle from key manager as a *keyset.Handle", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(hmacKeyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)

		mockKMS := mockKeyManager{}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(mockKMS, mockStoreProvider, nil,
			kmsservice.HMACSHA256Tag256Type)
		require.Equal(t, errKeySetHandleAssertionFailure, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Unexpected failure while getting key ID from store", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()
		err := mockStoreProvider.Store.Put(hmacKeyIDDBKeyName, []byte("testKeyID"))
		require.NoError(t, err)
		mockStoreProvider.Store.ErrGet = errTest

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(nil, mockStoreProvider, nil,
			kmsservice.HMACSHA256Tag256Type)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure while creating new HMAC key set", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()

		mockKMS := mockkms.KeyManager{CreateKeyErr: errTest}

		testMACValue := []byte("keyHandle")
		mockCrypto := crypto.Crypto{ComputeMACValue: testMACValue}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, &mockCrypto,
			kmsservice.HMACSHA256Tag256Type)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: unable to assert newly created key handle as a *keyset.Handle", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		km := createKMS(t)

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(km, mockStoreProvider, nil,
			kmsservice.HMACSHA256Tag256Type)
		require.EqualError(t, err, errTest.Error())
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure: error while putting new key ID in store", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		mockKMS := mockkms.KeyManager{}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, nil,
			kmsservice.HMACSHA256Tag256Type)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
	t.Run("Failure while computing MAC", func(t *testing.T) {
		mockStoreProvider := ariesmockstorage.NewMockStoreProvider()

		mockKMS := mockkms.KeyManager{}

		mockCrypto := crypto.Crypto{ComputeMACErr: errTest}

		keySetHandle, encodedVCIDIndexNameMAC, err := PrepareMACCrypto(&mockKMS, mockStoreProvider, &mockCrypto,
			kmsservice.HMACSHA256Tag256Type)
		require.Equal(t, errTest, err)
		require.Nil(t, keySetHandle)
		require.Empty(t, encodedVCIDIndexNameMAC)
	})
}

type mockKeyManager struct {
}

func (m mockKeyManager) Create(kt kmsservice.KeyType) (string, interface{}, error) {
	return "testKeyID", []byte("bad key type"), nil
}

func (m mockKeyManager) Get(keyID string) (interface{}, error) {
	return nil, nil
}

func (m mockKeyManager) Rotate(kt kmsservice.KeyType, keyID string) (string, interface{}, error) {
	panic("implement me")
}

func (m mockKeyManager) ExportPubKeyBytes(keyID string) ([]byte, error) {
	return nil, nil
}

func (m mockKeyManager) CreateAndExportPubKeyBytes(keyType kmsservice.KeyType) (string, []byte, error) {
	return "", nil, nil
}

func (m mockKeyManager) PubKeyBytesToHandle(pubKey []byte, keyType kmsservice.KeyType) (interface{}, error) {
	return nil, nil
}

func (m mockKeyManager) ImportPrivateKey(
	privKey interface{}, kt kmsservice.KeyType, opts ...kmsservice.PrivateKeyOpts) (string, interface{}, error) {
	return "", nil, nil
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}
