/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/verifiable"

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
	DID                     string                      // didResolution.DIDDocument.ID.
	Creator                 string                      // didResolution.DIDDocument.ID + "#" + authentication.ID.
	KMSKeyID                string                      // authentication.ID.
	SignatureType           vcsverifiable.SignatureType // issuer.vcConfig.signingAlgorithm.
	KeyType                 kms.KeyType
	Format                  vcsverifiable.Format               // VC format - LDP/JWT.
	SignatureRepresentation verifiable.SignatureRepresentation // For LDP only - proof/JWS.
	KMS                     keyManager
	VCStatusListType        StatusType // Type of VC status list
	SDJWT                   SDJWT
	DataIntegrityProof      DataIntegrityProofConfig
}
