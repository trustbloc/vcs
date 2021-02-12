/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// DIDResolver resolves DIDs.
type DIDResolver interface {
	Accept(method string) bool
	Read(did string, options ...vdr.ResolveOption) (*did.DocResolution, error)
}

// KMS key manager.
type KMS interface {
	Get(kid string) (interface{}, error)
	PubKeyBytesToHandle([]byte, kms.KeyType) (interface{}, error)
}

// Crypto primitives.
type Crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
	Verify(sig, msg []byte, kh interface{}) error
}
