/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"crypto"

	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

// SDJWT represents the SD-JWT configuration.
type SDJWT struct {
	Enable  bool                `json:"enable,omitempty"`
	HashAlg crypto.Hash         `json:"hashAlg,omitempty"`
	Version common.SDJWTVersion `json:"version,omitempty"`
}
