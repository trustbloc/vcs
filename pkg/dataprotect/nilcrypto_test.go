/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
)

func TestNilDataProtectorEncryptDecrypt(t *testing.T) {
	nilDataProtector := dataprotect.NewNilDataProtector()
	testData := []byte("This is a sample text to demonstrate the NilDataProtector encryption and decryption process.")

	encryptedData, err := nilDataProtector.Encrypt(context.Background(), testData)
	assert.NoError(t, err, "Failed to encrypt data")
	assert.Equal(t, testData, encryptedData.Encrypted, "Encrypted data should be the same as original data")

	decryptedData, err := nilDataProtector.Decrypt(context.Background(), encryptedData)
	assert.NoError(t, err, "Failed to decrypt data")
	assert.Equal(t, testData, decryptedData, "Decrypted data should be the same as original data")
}
