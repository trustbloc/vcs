/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"crypto"

	"github.com/trustbloc/vc-go/sdjwt/common"
)

// SDJWT represents the SD-JWT configuration.
type SDJWT struct {
	Enable  bool                `json:"enable,omitempty"`
	HashAlg crypto.Hash         `json:"hashAlg,omitempty"`
	Version common.SDJWTVersion `json:"version,omitempty"`
}
