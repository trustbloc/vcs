/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifycredential -source=verifycredential_service.go -mock_names revocationVCGetter=MockRevocationVCGetter

package verifycredential

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

const (
	revokedMsg = "revoked"
)

type revocationVCGetter interface {
	GetRevocationVC(statusURL string) (*verifiable.Credential, error)
}

// CredentialsVerificationCheckResult resp containing failure check details.
type CredentialsVerificationCheckResult struct {
	Check              string
	Error              string
	VerificationMethod string
}

// Options represents options for verify credential.
type Options struct {
	// Challenge is added to the proof.
	Challenge string

	// Domain is added to the proof.
	Domain string
}

type Config struct {
	RevocationVCGetter revocationVCGetter
	DocumentLoader     ld.DocumentLoader
	VDR                vdrapi.Registry
}

type Service struct {
	revocationVCGetter revocationVCGetter
	documentLoader     ld.DocumentLoader
	vdr                vdrapi.Registry
}

func New(config *Config) *Service {
	return &Service{
		revocationVCGetter: config.RevocationVCGetter,
		documentLoader:     config.DocumentLoader,
		vdr:                config.VDR,
	}
}

func (s *Service) VerifyCredential(credential *verifiable.Credential, opts *Options,
	profile *profileapi.Verifier) ([]CredentialsVerificationCheckResult, error) {
	checks := profile.Checks.Credential

	var result []CredentialsVerificationCheckResult

	if checks.Proof {
		vcBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, fmt.Errorf("unexpected error on credential marshal: %w", err)
		}

		err = s.ValidateCredentialProof(vcBytes, opts.Challenge, opts.Domain, false)
		if err != nil {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "proof",
				Error: err.Error(),
			})
		}
	}
	if checks.Status {
		err := s.ValidateVCStatus(credential.Status, credential.Issuer.ID)
		if err != nil {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "credentialStatus",
				Error: err.Error(),
			})
		}
	}

	return result, nil
}

func (s *Service) parseAndVerifyVCStrictMode(vcBytes []byte) (*verifiable.Credential, error) {
	cred, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithStrictValidation(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	)
	return cred, err
}

func (s *Service) ValidateCredentialProof(vcByte []byte, proofChallenge, proofDomain string, vcInVPValidation bool) error { // nolint: lll,gocyclo
	credential, err := s.parseAndVerifyVCStrictMode(vcByte)
	if err != nil {
		return fmt.Errorf("verifiable credential proof validation error : %w", err)
	}

	if len(credential.JWT) > 0 {
		return nil
	}

	if len(credential.Proofs) == 0 {
		return errors.New("verifiable credential doesn't contains proof")
	}

	// TODO https://github.com/trustbloc/vcs/issues/412 figure out the process when vc has more than one proof
	proof := credential.Proofs[0]

	if !vcInVPValidation {
		// validate challenge
		if validateErr := crypto.ValidateProofKey(proof, crypto.Challenge, proofChallenge); validateErr != nil {
			return validateErr
		}

		// validate domain
		if validateErr := crypto.ValidateProofKey(proof, crypto.Domain, proofDomain); validateErr != nil {
			return validateErr
		}
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

	// validate if issuer matches the controller of verification method
	if credential.Issuer.ID != didDoc.ID {
		return fmt.Errorf("controller of verification method doesn't match the issuer")
	}

	// validate proof purpose
	if err := crypto.ValidateProof(proof, verificationMethod, didDoc); err != nil {
		return fmt.Errorf("verifiable credential proof purpose validation error : %w", err)
	}

	return nil
}

func (s *Service) ValidateVCStatus(vcStatus *verifiable.TypedID, issuer string) error {
	// validate vc status
	if err := s.validateVCStatus(vcStatus); err != nil {
		return err
	}

	statusListIndex, err := strconv.Atoi(vcStatus.CustomFields[credentialstatus.StatusListIndex].(string))
	if err != nil {
		return err
	}

	revocationVC, err := s.revocationVCGetter.GetRevocationVC(
		vcStatus.CustomFields[credentialstatus.StatusListCredential].(string))
	if err != nil {
		return err
	}

	if revocationVC.Issuer.ID != issuer {
		return fmt.Errorf("issuer of the credential do not match vc revocation list issuer")
	}

	credSubject, ok := revocationVC.Subject.([]verifiable.Subject)
	if !ok {
		return fmt.Errorf("invalid subject field structure")
	}

	if credSubject[0].CustomFields[credentialstatus.StatusPurpose].(string) !=
		vcStatus.CustomFields[credentialstatus.StatusPurpose].(string) {
		return fmt.Errorf("vc statusPurpose not matching statusListCredential statusPurpose")
	}

	bitString, err := utils.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	if err != nil {
		return fmt.Errorf("failed to decode bits: %w", err)
	}

	bitSet, err := bitString.Get(statusListIndex)
	if err != nil {
		return err
	}

	if bitSet {
		return errors.New(revokedMsg)
	}

	return nil
}

func (s *Service) validateVCStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != credentialstatus.StatusList2021Entry {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[credentialstatus.StatusListIndex] == nil {
		return fmt.Errorf("statusListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[credentialstatus.StatusListCredential] == nil {
		return fmt.Errorf("statusListCredential field not exist in vc status")
	}

	if vcStatus.CustomFields[credentialstatus.StatusPurpose] == nil {
		return fmt.Errorf("statusPurpose field not exist in vc status")
	}

	return nil
}
