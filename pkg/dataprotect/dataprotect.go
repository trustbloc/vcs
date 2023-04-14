/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"context"
)

//go:generate mockgen -source dataprotect.go -destination dataprotect_mocks_test.go -package dataprotect_test

type crypto interface {
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
}

type dataEncryptor interface {
	Decrypt(data []byte, key []byte) ([]byte, error)
	Encrypt(data []byte) ([]byte, []byte, error)
}

type DataProtector struct {
	keyProtector  crypto
	cryptoKeyID   string
	dataProtector dataEncryptor
}

func NewDataProtector(
	crypto crypto,
	cryptoKeyID string,
	dataEncryptor dataEncryptor,
) *DataProtector {
	return &DataProtector{
		keyProtector:  crypto,
		cryptoKeyID:   cryptoKeyID,
		dataProtector: dataEncryptor,
	}
}

type EncryptedData struct {
	Encrypted      []byte `json:"encrypted"`
	EncryptedKey   []byte `json:"encrypted_key"`
	EncryptedNonce []byte `json:"encrypted_nonce"`
}

func (d *DataProtector) Encrypt(_ context.Context, msg []byte) (*EncryptedData, error) {
	encrypted, key, err := d.dataProtector.Encrypt(msg)
	if err != nil {
		return nil, err
	}

	encryptedKey, nonce, err := d.keyProtector.Encrypt(key, nil, d.cryptoKeyID)
	if err != nil {
		return nil, err
	}

	return &EncryptedData{
		Encrypted:      encrypted,
		EncryptedNonce: nonce,
		EncryptedKey:   encryptedKey,
	}, nil
}

func (d *DataProtector) Decrypt(_ context.Context, data *EncryptedData) ([]byte, error) {
	decryptedKey, err := d.keyProtector.Decrypt(nil, data.EncryptedKey, data.EncryptedNonce, d.cryptoKeyID)
	if err != nil {
		return nil, err
	}

	plaintext, err := d.dataProtector.Decrypt(data.Encrypted, decryptedKey)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
