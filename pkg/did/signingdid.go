/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

// SigningDID contains information about profile signing did.
type SigningDID struct {
	DID            string
	Creator        string
	UpdateKeyURL   string
	RecoveryKeyURL string
}
