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
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
)

const (
	dataIntegrityProofContextV1 = "https://w3id.org/security/data-integrity/v1"
	dataIntegrityProofContextV2 = "https://w3id.org/security/data-integrity/v2"
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

	ariesSigner, _, err := c.GetSigner(signerData.KMSKeyID, signerData.KMS, signatureType)
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
	contexts := vc.Contents().Context
	if !lo.Contains(contexts, verifiable.V2ContextURI) { // for v2 its already embedded
		if lo.Contains(contexts, dataIntegrityProofContextV1) { // backward compatibility. Migrate old creds to v2
			contexts = lo.Filter(contexts, func(s string, _ int) bool {
				return s != dataIntegrityProofContextV1
			})
		}

		if !lo.Contains(contexts, dataIntegrityProofContextV2) {
			vc = vc.WithModifiedContext(append(contexts, dataIntegrityProofContextV2))
		}
	}

	err = vc.AddDataIntegrityProof(signingCtx, diSigner)
	if err != nil {
		return nil, fmt.Errorf("add data integrity proof: %w", err)
	}

	return vc, nil
}

func (c *Crypto) getDataIntegritySignerInitializer(
	dataIntegritySuiteType string,
	signer vc.SignerAlgorithm,
) (dataintegritysuite.SignerInitializer, error) {
	switch dataIntegritySuiteType { //nolint: exhaustive
	case ecdsa2019.SuiteType, ecdsa2019.SuiteTypeNew:
		return ecdsa2019.NewSignerInitializer(&ecdsa2019.SignerInitializerOptions{
			SignerGetter:     ecdsa2019.WithStaticSigner(signer),
			LDDocumentLoader: c.documentLoader,
		}), nil
	case eddsa2022.SuiteType:
		return eddsa2022.NewSignerInitializer(&eddsa2022.SignerInitializerOptions{
			SignerGetter:     eddsa2022.WithStaticSigner(signer),
			LDDocumentLoader: c.documentLoader,
		}), nil
	default:
		return nil, fmt.Errorf("data integrity suite \"%s\" unsupported", dataIntegritySuiteType)
	}
}
