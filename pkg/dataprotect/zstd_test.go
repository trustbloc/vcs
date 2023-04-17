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

func TestZStdCompress(t *testing.T) {
	data := []byte("Your test data here...")

	zstd := dataprotect.NewZStd()
	compressed, err := zstd.Compress(data)

	assert.NoError(t, err, "Compress should not return an error")
	assert.NotEqual(t, data, compressed, "Compressed data should not be equal to the input data")

	resp, err := zstd.Decompress(compressed)
	assert.NoError(t, err)
	assert.Equal(t, data, resp)
}

func TestZStdDecompress(t *testing.T) {
	data := []byte("Your test data here...")

	zstd := dataprotect.NewZStd()
	compressed, _ := zstd.Compress(data)
	decompressed, err := zstd.Decompress(compressed)

	assert.NoError(t, err, "Decompress should not return an error")
	assert.Equal(t, data, decompressed, "Decompressed data should be equal to the input data")
}
