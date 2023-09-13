/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"fmt"

	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/dataintegrity"
	dataintegritysuite "github.com/trustbloc/vc-go/dataintegrity/suite"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
)

const (
	dataIntegrityProofContext = "https://w3id.org/security/data-integrity/v1"
)

// signCredentialLDP adds verifiable.DataIntegrityProofContext to the VC.
func (c *Crypto) signCredentialLDPDataIntegrity(signerData *vc.Signer,
	vc *verifiable.Credential, opts ...SigningOpts) (*verifiable.Credential, error) {
	signOpts := &signingOpts{}
	// apply opts
	for _, opt := range opts {
		opt(signOpts)
	}

	if signOpts.Purpose == "" {
		signOpts.Purpose = AssertionMethod
	}

	signatureType := signerData.SignatureType
	if signOpts.SignatureType != "" {
		signatureType = signOpts.SignatureType
	}

	ariesSigner, _, err := c.getSigner(signerData.KMSKeyID, signerData.KMS, signatureType)
	if err != nil {
		return nil, err
	}

	signerSuite, err := c.getDataIntegritySignerInitializer(signerData.DataIntegrityProof.SuiteType, ariesSigner)
	if err != nil {
		return nil, fmt.Errorf("get data integrity signer initializer: %w", err)
	}

	diSigner, err := dataintegrity.NewSigner(&dataintegrity.Options{
		DIDResolver: c.vdr,
	}, signerSuite)
	if err != nil {
		return nil, fmt.Errorf("get data integority signer: %w", err)
	}

	signingCtx := &verifiable.DataIntegrityProofContext{
		SigningKeyID: signerData.Creator,
		CryptoSuite:  signerData.DataIntegrityProof.SuiteType,
		ProofPurpose: signOpts.Purpose,
		Created:      signOpts.Created,
		Domain:       signOpts.Domain,
		Challenge:    signOpts.Challenge,
	}

	// Update VC context for Data Integrity.
	if !lo.Contains(vc.Context, dataIntegrityProofContext) {
		vc.Context = append(vc.Context, dataIntegrityProofContext)
	}

	err = vc.AddDataIntegrityProof(signingCtx, diSigner)
	if err != nil {
		return nil, fmt.Errorf("add data integrity proof: %w", err)
	}

	return vc, nil
}

func (c *Crypto) getDataIntegritySignerInitializer(
	dataIntegritySuiteType string, signer vc.SignerAlgorithm) (dataintegritysuite.SignerInitializer, error) {
	switch dataIntegritySuiteType { //nolint: exhaustive
	case ecdsa2019.SuiteType:
		return ecdsa2019.NewSignerInitializer(&ecdsa2019.SignerInitializerOptions{
			SignerGetter:     ecdsa2019.WithStaticSigner(signer),
			LDDocumentLoader: c.documentLoader,
		}), nil
	default:
		return nil, fmt.Errorf("data integrity suite \"%s\" unsupported", dataIntegritySuiteType)
	}
}
