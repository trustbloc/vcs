/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

type NilZip struct {
}

func NewNilZip() *NilZip {
	return &NilZip{}
}

func (g *NilZip) Compress(input []byte) ([]byte, error) {
	return input, nil
}

func (g *NilZip) Decompress(input []byte) ([]byte, error) {
	return input, nil
}
