/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package versions

type credentialSubject struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	StatusPurpose string `json:"statusPurpose,omitempty"`
	EncodedList   string `json:"encodedList"`
}
