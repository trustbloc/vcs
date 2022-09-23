/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifypresentation -source=verifypresentation_service.go -mock_names vcVerifier=MockVcVerifier

package verifypresentation

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	"github.com/trustbloc/vcs/pkg/verifier"
)

type vcVerifier interface {
	ValidateCredentialProof(vcByte []byte, proofChallenge, proofDomain string, vcInVPValidation bool) error
	ValidateVCStatus(vcStatus *verifiable.TypedID, issuer string) error
}

type Config struct {
	VDR            vdrapi.Registry
	DocumentLoader ld.DocumentLoader
	VcVerifier     vcVerifier
}

type Service struct {
	vdr            vdrapi.Registry
	documentLoader ld.DocumentLoader
	vcVerifier     vcVerifier
}

type Options struct {
	Domain    string
	Challenge string
}

// PresentationVerificationCheckResult resp containing failure check details.
type PresentationVerificationCheckResult struct {
	Check string
	Error string
}

func New(config *Config) *Service {
	return &Service{
		vdr:            config.VDR,
		documentLoader: config.DocumentLoader,
		vcVerifier:     config.VcVerifier,
	}
}

func (s *Service) VerifyPresentation(
	presentation *verifiable.Presentation,
	profile *verifier.Profile,
	opts *Options) ([]PresentationVerificationCheckResult, error) {
	vpBytes, err := json.Marshal(presentation)
	if err != nil {
		return nil, fmt.Errorf("unexpected error on credential marshal: %w", err)
	}

	var result []PresentationVerificationCheckResult

	checks := profile.Checks.Presentation

	if checks.Proof {
		err = s.validatePresentationProof(vpBytes, opts)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "proof",
				Error: err.Error(),
			})
		}
	}

	return result, nil
}

func (s *Service) validatePresentationProof(vpBytes []byte, opts *Options) error { // nolint: gocyclo
	vp, err := s.parseAndVerifyPresentation(vpBytes, true, false)
	if err != nil {
		return fmt.Errorf("verifiable presentation proof validation error : %w", err)
	}

	return s.validateProofData(vp, opts)
}

func (s *Service) validateProofData(vp *verifiable.Presentation, opts *Options) error { // nolint: gocyclo
	if opts == nil {
		opts = &Options{}
	}

	if len(vp.Proofs) == 0 {
		return errors.New("verifiable presentation doesn't contains proof")
	}

	// TODO https://github.com/trustbloc/vcs/issues/412 figure out the process when vc has more than one proof
	proof := vp.Proofs[0]

	// validate challenge
	if validateErr := crypto.ValidateProofKey(proof, crypto.Challenge, opts.Challenge); validateErr != nil {
		return validateErr
	}

	// validate domain
	if validateErr := crypto.ValidateProofKey(proof, crypto.Domain, opts.Domain); validateErr != nil {
		return validateErr
	}

	// get the verification method
	verificationMethod, err := crypto.GetVerificationMethodFromProof(proof)
	if err != nil {
		return err
	}

	// get the did doc from verification method
	didDoc, err := diddoc.GetDIDDocFromVerificationMethod(verificationMethod, s.vdr)
	if err != nil {
		return err
	}

	// validate if holder matches the controller of verification method
	if vp.Holder != "" && vp.Holder != didDoc.ID {
		return fmt.Errorf("controller of verification method doesn't match the holder")
	}

	// validate proof purpose
	if err = crypto.ValidateProof(proof, verificationMethod, didDoc); err != nil {
		return fmt.Errorf("verifiable presentation proof purpose validation error : %w", err)
	}

	return nil
}

//nolint:funlen,gocyclo,gocognit
func (s *Service) parseAndVerifyPresentation(vpBytes []byte, validateCredentialProof,
	validateCredentialStatus bool) (*verifiable.Presentation, error) {
	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return nil, err
	}

	// verify if the credentials in vp are valid
	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}

		if validateCredentialProof {
			// verify if the credential in vp is valid
			err = s.vcVerifier.ValidateCredentialProof(vcBytes, "", "", true)
			if err != nil {
				return nil, err
			}
		}

		if validateCredentialStatus {
			vc, err := verifiable.ParseCredential(vcBytes,
				verifiable.WithDisabledProofCheck(),
				verifiable.WithJSONLDDocumentLoader(s.documentLoader))
			if err != nil {
				return nil, err
			}

			err = s.vcVerifier.ValidateVCStatus(vc.Status, vc.Issuer.ID)
			if err != nil {
				return nil, err
			}
		}
	}

	return vp, nil
}
