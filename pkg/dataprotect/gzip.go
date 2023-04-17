/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"bytes"
	"compress/gzip"
	"io"
)

type GZip struct {
}

func NewGzip() *GZip {
	return &GZip{}
}

// Compress takes a byte slice and returns a gzip compressed byte slice.
func (g *GZip) Compress(input []byte) ([]byte, error) {
	var compressedData bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedData)

	_, err := gzipWriter.Write(input)
	if err != nil {
		return nil, err
	}

	err = gzipWriter.Close()
	if err != nil {
		return nil, err
	}

	return compressedData.Bytes(), nil
}

// Decompress takes a gzip compressed byte slice and returns a decompressed byte slice.
func (g *GZip) Decompress(input []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(input))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = gzipReader.Close()
	}()

	data, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}

	return data, nil
}
