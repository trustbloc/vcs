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
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type vcVerifier interface {
	ValidateCredentialProof(vcByte []byte, proofChallenge, proofDomain string, vcInVPValidation, isJWT bool) error
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
	opts *Options,
	profile *profileapi.Verifier) ([]PresentationVerificationCheckResult, error) {
	var result []PresentationVerificationCheckResult

	if profile.Checks.Presentation.Proof {
		vpBytes := []byte(presentation.JWT)
		var err error

		if presentation.JWT == "" {
			vpBytes, err = json.Marshal(presentation)
			if err != nil {
				return nil, fmt.Errorf("unexpected error on credential marshal: %w", err)
			}
		}

		err = s.validatePresentationProof(vpBytes, opts)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "proof",
				Error: err.Error(),
			})
		}
	}

	if profile.Checks.Credential.Proof {
		err := s.validateCredentialsProof(presentation)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialProof",
				Error: err.Error(),
			})
		}
	}

	if profile.Checks.Credential.Status {
		err := s.validateCredentialsStatus(presentation)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialStatus",
				Error: err.Error(),
			})
		}
	}

	if err := s.validateHolderBinding(presentation); err != nil {
		result = append(result, PresentationVerificationCheckResult{
			Check: "credentialHolderBinding",
			Error: err.Error(),
		})
	}

	return result, nil
}

func (s *Service) validatePresentationProof(vpBytes []byte, opts *Options) error {
	vp, err := verifiable.ParsePresentation(
		vpBytes,
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("verifiable presentation proof validation error : %w", err)
	}
	if vp.JWT == "" {
		return s.validateProofData(vp, opts)
	}
	return nil
}

func (s *Service) validateProofData(vp *verifiable.Presentation, opts *Options) error {
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

func (s *Service) validateCredentialsProof(vp *verifiable.Presentation) error {
	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return err
		}

		err = s.vcVerifier.ValidateCredentialProof(vcBytes, "", "", true, vp.JWT != "")
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) validateCredentialsStatus(vp *verifiable.Presentation) error {
	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return err
		}

		vc, err := verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader))
		if err != nil {
			return err
		}

		err = s.vcVerifier.ValidateVCStatus(vc.Status, vc.Issuer.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) validateHolderBinding(vp *verifiable.Presentation) error {
	if vp == nil {
		return nil
	}

	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return err
		}

		vc, err := verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader))
		if err != nil {
			return err
		}

		subjects, ok := vc.Subject.([]verifiable.Subject)
		if !ok {
			return fmt.Errorf("can not map credentials subjects")
		}

		found := false
		for _, sub := range subjects {
			if sub.ID == vp.Holder {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("holder binding check failed")
		}
	}

	return nil
}
