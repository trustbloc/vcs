/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cryptosetup

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage"
)

const (
	masterKeyStoreName  = "masterkey"
	masterKeyDBKeyName  = masterKeyStoreName
	vcIDEDVIndexName    = "vcID"
	keyIDStoreName      = "keyid"
	keyIDDBKeyName      = keyIDStoreName
	signingKeyStoreName = "signingkey"
	signingKeyDBKeyName = signingKeyStoreName
)

var errKeySetHandleAssertionFailure = errors.New("unable to assert key handle as a key set handle pointer")

type legacyKMSProvider struct {
	kms legacykms.KeyManager
}

func (p legacyKMSProvider) LegacyKMS() legacykms.KeyManager {
	return p.kms
}

// PrepareMasterKeyReader prepares a master key reader for secret lock usage
func PrepareMasterKeyReader(kmsSecretsStoreProvider ariesstorage.Provider) (*bytes.Reader, error) {
	masterKeyStore, err := kmsSecretsStoreProvider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			masterKeyRaw := random.GetRandomBytes(uint32(32))
			masterKey = []byte(base64.URLEncoding.EncodeToString(masterKeyRaw))

			putErr := masterKeyStore.Put(masterKeyDBKeyName, masterKey)
			if putErr != nil {
				return nil, putErr
			}
		} else {
			return nil, err
		}
	}

	masterKeyReader := bytes.NewReader(masterKey)

	return masterKeyReader, nil
}

// PrepareMACCrypto prepares necessary MAC crypto data for edge-service operations
func PrepareMACCrypto(keyManager kms.KeyManager,
	storeProvider storage.Provider, crypto ariescrypto.Crypto) (*keyset.Handle, string, error) {
	keyHandle, err := prepareKeyHandle(storeProvider, keyManager)
	if err != nil {
		return nil, "", err
	}

	vcIDIndexNameMAC, err := crypto.ComputeMAC([]byte(vcIDEDVIndexName), keyHandle)
	if err != nil {
		return nil, "", err
	}

	return keyHandle, base64.URLEncoding.EncodeToString(vcIDIndexNameMAC), nil
}

func prepareKeyHandle(storeProvider storage.Provider, keyManager kms.KeyManager) (*keyset.Handle, error) {
	keyIDStore, err := prepareKeyIDStore(storeProvider)
	if err != nil {
		return nil, err
	}

	var kh *keyset.Handle

	keyIDBytes, err := keyIDStore.Get(keyIDDBKeyName)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			keyID, keyHandleUntyped, createErr := keyManager.Create(kms.HMACSHA256Tag256Type)
			if createErr != nil {
				return nil, createErr
			}

			var ok bool

			kh, ok = keyHandleUntyped.(*keyset.Handle)
			if !ok {
				return nil, errKeySetHandleAssertionFailure
			}

			err = keyIDStore.Put(keyIDDBKeyName, []byte(keyID))
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		keyHandleUntyped, getErr := keyManager.Get(string(keyIDBytes))
		if getErr != nil {
			return nil, getErr
		}

		var ok bool

		kh, ok = keyHandleUntyped.(*keyset.Handle)
		if !ok {
			return nil, errKeySetHandleAssertionFailure
		}
	}

	return kh, nil
}

func prepareKeyIDStore(storeProvider storage.Provider) (storage.Store, error) {
	err := storeProvider.CreateStore(keyIDStoreName)
	if err != nil {
		if !errors.Is(err, storage.ErrDuplicateStore) {
			return nil, err
		}
	}

	return storeProvider.OpenStore(keyIDStoreName)
}

// PrepareJWECrypto prepares necessary JWE crypto data for edge-service operations
func PrepareJWECrypto(legacyKMS legacykms.KeyManager,
	storeProvider storage.Provider) (string, *authcrypt.Packer, error) {
	// ToDo: Switch to localKMS. https://github.com/trustbloc/edge-service/issues/309
	kmsProv := legacyKMSProvider{kms: legacyKMS}

	packer := authcrypt.New(kmsProv)

	signingKeyStore, err := prepareSigningKeyStore(storeProvider)
	if err != nil {
		return "", nil, err
	}

	var signingKey string

	signingKeyBytes, err := signingKeyStore.Get(signingKeyDBKeyName)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			var createKeySetErr error

			_, signingKey, createKeySetErr = legacyKMS.CreateKeySet()
			if createKeySetErr != nil {
				return "", nil, createKeySetErr
			}

			err = signingKeyStore.Put(signingKeyDBKeyName, []byte(signingKey))
			if err != nil {
				return "", nil, err
			}
		} else {
			return "", nil, err
		}
	} else {
		signingKey = string(signingKeyBytes)
	}

	return signingKey, packer, nil
}

func prepareSigningKeyStore(storeProvider storage.Provider) (storage.Store, error) {
	err := storeProvider.CreateStore(signingKeyStoreName)
	if err != nil {
		if !errors.Is(err, storage.ErrDuplicateStore) {
			return nil, err
		}
	}

	return storeProvider.OpenStore(signingKeyStoreName)
}
