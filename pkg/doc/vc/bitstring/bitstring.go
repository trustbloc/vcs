/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bitstring

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"

	"github.com/multiformats/go-multibase"
)

const (
	bitsPerByte = 8
	one         = 0x1
	bitOffset   = 7
)

// BitString struct.
type BitString struct {
	bits              []byte
	multibaseEncoding multibase.Encoding
	bitPosition       func(position int) int
}

type Opt func(*options)

type options struct {
	multibaseEncoding multibase.Encoding
}

// WithMultibaseEncoding sets the multibase encoding.
func WithMultibaseEncoding(value multibase.Encoding) Opt {
	return func(options *options) {
		options.multibaseEncoding = value
	}
}

// NewBitString return bitstring.
func NewBitString(length int, opts ...Opt) *BitString {
	size := 1 + ((length - 1) / bitsPerByte)

	return newBitString(make([]byte, size), opts)
}

func newBitString(bits []byte, opts []Opt) *BitString {
	options := &options{}

	for _, opt := range opts {
		opt(options)
	}

	b := &BitString{
		bits:              bits,
		multibaseEncoding: options.multibaseEncoding,
	}

	if options.multibaseEncoding != multibase.Encoding(0) {
		// VC DM2.0 BitstringStatusList uses multibase encoding and requires bits
		// to be set left-to-right.
		b.bitPosition = func(position int) int {
			return bitOffset - (position % bitsPerByte)
		}
	} else {
		// Maintain backward compatibility with the previous implementation,
		// which sets bits right-to-left.
		b.bitPosition = func(position int) int {
			return position % bitsPerByte
		}
	}

	return b
}

// DecodeBits decode bits.
func DecodeBits(encodedBits string, opts ...Opt) (*BitString, error) {
	options := &options{}

	for _, opt := range opts {
		opt(options)
	}

	var decodedBits []byte

	if options.multibaseEncoding != multibase.Encoding(0) {
		var encoding multibase.Encoding
		var err error

		encoding, decodedBits, err = multibase.Decode(encodedBits)
		if err != nil {
			return nil, err
		}

		if encoding != options.multibaseEncoding {
			return nil, fmt.Errorf("encoding not supported: %d", encoding)
		}
	} else {
		var err error

		decodedBits, err = base64.RawURLEncoding.DecodeString(encodedBits)
		if err != nil {
			return nil, err
		}
	}

	b := bytes.NewReader(decodedBits)

	r, err := gzip.NewReader(b)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}

	return newBitString(buf.Bytes(), opts), nil
}

// Set bit.
func (b *BitString) Set(position int, bitSet bool) error {
	nByte := position / bitsPerByte
	nBit := b.bitPosition(position)

	if position < 0 || nByte > len(b.bits)-1 {
		return fmt.Errorf("position is invalid")
	}

	if bitSet {
		mask := byte(one << nBit)
		b.bits[nByte] |= mask
	} else {
		mask := ^byte(one << nBit)
		b.bits[nByte] &= mask
	}

	return nil
}

// Get bit.
func (b *BitString) Get(position int) (bool, error) {
	nByte := position / bitsPerByte
	nBit := b.bitPosition(position)

	if position < 0 || nByte > len(b.bits)-1 {
		return false, fmt.Errorf("position is invalid")
	}

	bitValue := (b.bits[nByte] & (one << nBit)) != 0

	return bitValue, nil
}

// EncodeBits encode bits.
func (b *BitString) EncodeBits() (string, error) {
	var buf bytes.Buffer

	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b.bits); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	if b.multibaseEncoding == multibase.Encoding(0) {
		return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
	}

	return multibase.Encode(b.multibaseEncoding, buf.Bytes())
}
