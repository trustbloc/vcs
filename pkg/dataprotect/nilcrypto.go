/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

type NilCrypto struct {
}

func NewNilCrypto() *NilCrypto {
	return &NilCrypto{}
}

func (n *NilCrypto) Encrypt(msg, _ []byte, _ interface{}) ([]byte, []byte, error) {
	return msg, nil, nil
}

func (n *NilCrypto) Decrypt(_, aad, _ []byte, _ interface{}) ([]byte, error) {
	return aad, nil
}
