/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
)

// BitString struct
type BitString struct {
	bits []uint8
}

// NewBitString return bitstring
func NewBitString(size int) *BitString {
	return &BitString{bits: make([]uint8, size)}
}

// DecodeBits decode bits
func DecodeBits(encodedBits string) (*BitString, error) {
	decodedBits, err := base64.StdEncoding.DecodeString(encodedBits)
	if err != nil {
		return nil, err
	}

	b := bytes.NewReader(decodedBits)

	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}

	return &BitString{bits: buf.Bytes()}, nil
}

// Set bit
func (b *BitString) Set(position int, bitSet bool) error {
	if position < 0 || position >= len(b.bits) {
		return fmt.Errorf("position is invalid")
	}

	if bitSet {
		b.bits[position] = 1
		return nil
	}

	b.bits[position] = 0

	return nil
}

// Get bit
func (b *BitString) Get(position int) (bool, error) {
	if position < 0 || position >= len(b.bits) {
		return false, fmt.Errorf("position is invalid")
	}

	if b.bits[position] == 1 {
		return true, nil
	}

	return false, nil
}

// EncodeBits encode bits
func (b *BitString) EncodeBits() (string, error) {
	var buf bytes.Buffer

	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b.bits); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
