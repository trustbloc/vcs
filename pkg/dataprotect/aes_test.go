/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
)

func TestEncryptDecrypt(t *testing.T) {
	aes := dataprotect.NewAES(256)
	var finalData []byte
	for len(finalData) < 2000000 {
		finalData = append(finalData, []byte("This is a secret message")...)
	}

	ciphertext, key, err := aes.Encrypt(finalData)
	if err != nil {
		t.Fatalf("Error encrypting data: %v", err)
	}

	plaintext, err := aes.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Error decrypting data: %v", err)
	}

	assert.Equal(t, finalData, plaintext)
}

func TestTooLongKey(t *testing.T) {
	aes := dataprotect.NewAES(512)
	ciphertext, key, err := aes.Encrypt([]byte("This is a secret message"))
	assert.Empty(t, ciphertext)
	assert.Empty(t, key)
	assert.ErrorContains(t, err, "invalid key size 64")
}
