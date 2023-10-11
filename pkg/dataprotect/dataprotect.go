/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"context"

	"github.com/trustbloc/kms-go/wrapper/api"
)

//go:generate mockgen -source dataprotect.go -destination dataprotect_mocks_test.go -package dataprotect_test

type encDec interface {
	Encrypt(msg []byte, aad []byte, kid string) (cipher []byte, nonce []byte, err error)
	Decrypt(cipher []byte, aad []byte, nonce []byte, kid string) (msg []byte, err error)
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
	cryptoKeyID    string
	dataProtector  dataEncryptor
	dataCompressor DataCompressor
	encDec         api.EncrypterDecrypter
}

func NewDataProtector(
	keyEncryptor encDec,
	cryptoKeyID string,
	dataEncryptor dataEncryptor,
	dataCompressor DataCompressor,
) *DataProtector {
	return &DataProtector{
		cryptoKeyID:    cryptoKeyID,
		dataProtector:  dataEncryptor,
		dataCompressor: dataCompressor,
		encDec:         keyEncryptor,
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

	encryptedKey, nonce, err := d.encDec.Encrypt(key, nil, d.cryptoKeyID)
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
	decryptedKey, err := d.encDec.Decrypt(data.EncryptedKey, nil, data.EncryptedNonce, d.cryptoKeyID)
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
