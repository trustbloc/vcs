/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type keyManager interface {
	NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (SignerAlgorithm, error)
}

type SignerAlgorithm interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

// Signer contains information about vc signer, usually this is credential issuer.
type Signer struct {
	DID                     string
	Creator                 string
	SignatureType           vcsverifiable.SignatureType
	SignatureRepresentation verifiable.SignatureRepresentation
	KMS                     keyManager
}
