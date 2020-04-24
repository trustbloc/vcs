/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/google/tink/go/keyset"
	kmsservice "github.com/hyperledger/aries-framework-go/pkg/kms"
)

// KeyManager mocks a local Key Management Service
type KeyManager struct {
	CreateKeyID            string
	CreateKeyValue         *keyset.Handle
	CreateKeyErr           error
	GetKeyValue            *keyset.Handle
	GetKeyErr              error
	RotateKeyID            string
	RotateKeyValue         *keyset.Handle
	RotateKeyErr           error
	ExportPubKeyBytesValue []byte
	ExportPubKeyBytesErr   error
}

// Create a new mock ey/keyset/key handle for the type kt
func (k *KeyManager) Create(kt kmsservice.KeyType) (string, interface{}, error) {
	if k.CreateKeyErr != nil {
		return "", nil, k.CreateKeyErr
	}

	return k.CreateKeyID, k.CreateKeyValue, nil
}

// Get a mock key handle for the given keyID
func (k *KeyManager) Get(keyID string) (interface{}, error) {
	if k.GetKeyErr != nil {
		return nil, k.GetKeyErr
	}

	return k.GetKeyValue, nil
}

// Rotate returns a mocked rotated keyset handle and its ID
func (k *KeyManager) Rotate(kt kmsservice.KeyType, keyID string) (string, interface{}, error) {
	if k.RotateKeyErr != nil {
		return "", nil, k.RotateKeyErr
	}

	return k.RotateKeyID, k.RotateKeyValue, nil
}

// ExportPubKeyBytes export public key
func (k *KeyManager) ExportPubKeyBytes(id string) ([]byte, error) {
	return k.ExportPubKeyBytesValue, k.ExportPubKeyBytesErr
}
