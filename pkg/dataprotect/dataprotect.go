/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"context"
)

//go:generate mockgen -source dataprotect.go -destination dataprotect_mocks_test.go -package dataprotect_test

type Crypto interface {
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
}

type dataEncryptor interface {
	Decrypt(data []byte, key []byte) ([]byte, error)
	Encrypt(data []byte) ([]byte, []byte, error)
}

type DataCompressor interface {
	Decompress(input []byte) ([]byte, error)
	Compress(input []byte) ([]byte, error)
}

type DataProtector struct {
	keyProtector   Crypto
	cryptoKeyID    string
	dataProtector  dataEncryptor
	dataCompressor DataCompressor
}

func NewDataProtector(
	crypto Crypto,
	cryptoKeyID string,
	dataEncryptor dataEncryptor,
	dataCompressor DataCompressor,
) *DataProtector {
	return &DataProtector{
		keyProtector:   crypto,
		cryptoKeyID:    cryptoKeyID,
		dataProtector:  dataEncryptor,
		dataCompressor: dataCompressor,
	}
}

type EncryptedData struct {
	Encrypted      []byte `json:"encrypted"`
	EncryptedKey   []byte `json:"encrypted_key"`
	EncryptedNonce []byte `json:"encrypted_nonce"`
}

func (d *DataProtector) Encrypt(_ context.Context, msg []byte) (*EncryptedData, error) {
	msg, err := d.dataCompressor.Compress(msg)
	if err != nil {
		return nil, err
	}

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

	plaintext, err = d.dataCompressor.Decompress(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
