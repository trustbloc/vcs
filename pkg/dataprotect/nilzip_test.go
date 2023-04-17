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

func TestNullZipCompress(t *testing.T) {
	data := []byte("Your test data here...")

	nullZip := dataprotect.NewNilZip()
	compressed, err := nullZip.Compress(data)

	assert.NoError(t, err, "Compress should not return an error")
	assert.Equal(t, data, compressed, "Compressed data should be equal to the input data")
}

func TestNullZipDecompress(t *testing.T) {
	data := []byte("Your test data here...")

	nullZip := dataprotect.NewNilZip()
	decompressed, err := nullZip.Decompress(data)

	assert.NoError(t, err, "Decompress should not return an error")
	assert.Equal(t, data, decompressed, "Decompressed data should be equal to the input data")
}
