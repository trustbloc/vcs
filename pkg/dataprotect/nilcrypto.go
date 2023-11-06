/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import "context"

type NilDataProtector struct {
}

func NewNilDataProtector() *NilDataProtector {
	return &NilDataProtector{}
}

func (n *NilDataProtector) Encrypt(_ context.Context, msg []byte) (*EncryptedData, error) {
	return &EncryptedData{
		Encrypted:      msg,
		EncryptedKey:   nil,
		EncryptedNonce: nil,
	}, nil
}

func (n *NilDataProtector) Decrypt(_ context.Context, encryptedData *EncryptedData) ([]byte, error) {
	return encryptedData.Encrypted, nil
}
