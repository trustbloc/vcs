/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"context"

	"github.com/samber/lo"
)

//go:generate mockgen -source dataprotect.go -destination dataprotect_mocks_test.go -package dataprotect_test

type crypto interface {
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
}

type DataProtector struct {
	crypto       crypto
	maxChunkSize int
	cryptoKeyID  string
}

func NewDataProtector(crypto crypto, maxChunkSize int, cryptoKeyID string) *DataProtector {
	return &DataProtector{
		crypto:       crypto,
		maxChunkSize: maxChunkSize,
		cryptoKeyID:  cryptoKeyID,
	}
}

type EncryptedChunk struct {
	Encrypted      []byte `json:"encrypted"`
	EncryptedNonce []byte `json:"encrypted_nonce"`
}

func (d *DataProtector) Encrypt(_ context.Context, msg []byte) ([]*EncryptedChunk, error) {
	var final []*EncryptedChunk

	for _, c := range lo.Chunk(msg, d.maxChunkSize) {
		encrypted, nonce, err := d.crypto.Encrypt(c, nil, d.cryptoKeyID)
		if err != nil {
			return nil, err
		}

		final = append(final, &EncryptedChunk{
			Encrypted:      encrypted,
			EncryptedNonce: nonce,
		})
	}

	return final, nil
}

func (d *DataProtector) Decrypt(_ context.Context, chunks []*EncryptedChunk) ([]byte, error) {
	var final []byte

	for _, c := range chunks {
		encrypted, err := d.crypto.Decrypt(nil, c.Encrypted, c.EncryptedNonce, d.cryptoKeyID)
		if err != nil {
			return nil, err
		}

		final = append(final, encrypted...)
	}

	return final, nil
}
