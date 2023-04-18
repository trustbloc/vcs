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

func TestNilCryptoEncryptDecrypt(t *testing.T) {
	nilCrypto := dataprotect.NewNilCrypto()
	testData := []byte("This is a sample text to demonstrate the NilCrypto encryption and decryption process.")

	encryptedData, _, err := nilCrypto.Encrypt(testData, nil, nil)
	assert.NoError(t, err, "Failed to encrypt data")
	assert.Equal(t, testData, encryptedData, "Encrypted data should be the same as original data")

	decryptedData, err := nilCrypto.Decrypt(nil, encryptedData, nil, nil)
	assert.NoError(t, err, "Failed to decrypt data")
	assert.Equal(t, testData, decryptedData, "Decrypted data should be the same as original data")
}

func TestNilCryptoEncryptError(t *testing.T) {
	nilCrypto := dataprotect.NewNilCrypto()
	testData := make([]byte, 0)

	_, _, err := nilCrypto.Encrypt(testData, nil, nil)
	assert.NoError(t, err, "Encrypt should not return an error when encrypting empty data")
}

func TestNilCryptoDecryptError(t *testing.T) {
	nilCrypto := dataprotect.NewNilCrypto()
	testData := make([]byte, 0)

	_, err := nilCrypto.Decrypt(nil, testData, nil, nil)
	assert.NoError(t, err, "Decrypt should not return an error when decrypting empty data")
}
