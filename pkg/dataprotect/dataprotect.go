/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"context"

	"github.com/gammazero/workerpool"
	"github.com/samber/lo"
)

//go:generate mockgen -source dataprotect.go -destination dataprotect_mocks_test.go -package dataprotect_test

type crypto interface {
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
}

type DataProtector struct {
	crypto             crypto
	maxChunkSize       int
	cryptoKeyID        string
	routinesPerRequest int
}

func NewDataProtector(crypto crypto, maxChunkSize int, cryptoKeyID string, routinesPerRequest int) *DataProtector {
	if routinesPerRequest < 1 {
		routinesPerRequest = 1
	}

	return &DataProtector{
		crypto:             crypto,
		maxChunkSize:       maxChunkSize,
		cryptoKeyID:        cryptoKeyID,
		routinesPerRequest: routinesPerRequest,
	}
}

type EncryptedChunk struct {
	Encrypted      []byte `json:"encrypted"`
	EncryptedNonce []byte `json:"encrypted_nonce"`
}

func (d *DataProtector) Encrypt(_ context.Context, msg []byte) ([]*EncryptedChunk, error) {
	var finalErr error

	chunks := lo.Chunk(msg, d.maxChunkSize)
	final := make([]*EncryptedChunk, 0, len(chunks))
	pool := workerpool.New(d.routinesPerRequest)

	for _, c1 := range chunks {
		c := c1
		ch := &EncryptedChunk{}
		final = append(final, ch)

		pool.Submit(func() {
			if finalErr != nil {
				return
			}

			encrypted, nonce, err := d.crypto.Encrypt(c, nil, d.cryptoKeyID)
			if err != nil {
				finalErr = err
				return
			}
			ch.Encrypted = encrypted
			ch.EncryptedNonce = nonce
		})
	}

	pool.StopWait()
	if finalErr != nil {
		return nil, finalErr
	}

	return final, nil
}

func (d *DataProtector) Decrypt(_ context.Context, chunks []*EncryptedChunk) ([]byte, error) {
	pool := workerpool.New(d.routinesPerRequest)
	var finalErr error

	decryptedChunks := make([][]byte, len(chunks))
	for i1, c1 := range chunks {
		c := c1
		i := i1

		pool.Submit(func() {
			if finalErr != nil {
				return
			}

			encrypted, err := d.crypto.Decrypt(nil, c.Encrypted, c.EncryptedNonce, d.cryptoKeyID)
			if err != nil {
				finalErr = err
				return
			}

			decryptedChunks[i] = encrypted
		})
	}

	pool.StopWait()
	if finalErr != nil {
		return nil, finalErr
	}

	var final []byte
	for _, ch := range decryptedChunks {
		final = append(final, ch...)
	}

	return final, nil
}
