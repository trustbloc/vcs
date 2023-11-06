/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import "context"

type Protector interface {
	Encrypt(ctx context.Context, msg []byte) (*EncryptedData, error)
	Decrypt(ctx context.Context, encryptedData *EncryptedData) ([]byte, error)
}
