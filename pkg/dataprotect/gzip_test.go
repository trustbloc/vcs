/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect_test

import (
	"bytes"
	"testing"

	"github.com/trustbloc/vcs/pkg/dataprotect"
)

func TestGZipCompressDecompress(t *testing.T) {
	gzipProcessor := &dataprotect.GZip{}
	testData := []byte("This is a sample text to demonstrate GZip compression and decompression in Golang." +
		"p[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[['")

	compressedData, err := gzipProcessor.Compress(testData)
	if err != nil {
		t.Errorf("Failed to compress data: %v", err)
	}

	if len(compressedData) >= len(testData) {
		t.Errorf("Compressed data should be smaller than original data")
	}

	decompressedData, err := gzipProcessor.Decompress(compressedData)
	if err != nil {
		t.Errorf("Failed to decompress data: %v", err)
	}

	if !bytes.Equal(decompressedData, testData) {
		t.Errorf("Decompressed data does not match original data")
	}
}

func TestGZipDecompressError(t *testing.T) {
	gzipProcessor := &dataprotect.GZip{}
	testData := []byte("This is not a valid compressed data")

	_, err := gzipProcessor.Decompress(testData)
	if err == nil {
		t.Errorf("Decompress should return an error when decompressing invalid data")
	}
}
