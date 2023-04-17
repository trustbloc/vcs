/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

type ZStd struct {
}

func NewZStd() *ZStd {
	return &ZStd{}
}

func (g *ZStd) Compress(input []byte) ([]byte, error) {
	compressor, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}

	return compressor.EncodeAll(input, nil), nil
}

func (g *ZStd) Decompress(input []byte) ([]byte, error) {
	decompressor, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("error creating zstd decompressor: %w", err)
	}
	defer decompressor.Close()

	decompressedData, err := decompressor.DecodeAll(input, nil)
	if err != nil {
		return nil, fmt.Errorf("error reading decompressed data: %w", err)
	}

	return decompressedData, nil
}
