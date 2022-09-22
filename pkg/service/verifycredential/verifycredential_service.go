/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifycredential -source=verifycredential_service.go -mock_names vcStatusManager=MockVcStatusManager

package verifycredential

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const (
	challenge          = "challenge"
	domain             = "domain"
	proofPurpose       = "proofPurpose"
	verificationMethod = "verificationMethod"
	successMsg         = "success"
)

type vcStatusManager interface {
	GetRevocationListVC(statusURL string) (*verifiable.Credential, error)
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

type VerificationStatus struct {
	Verified bool
	Message  string
}

type Config struct {
	VcStatusManager vcStatusManager
	DocumentLoader  ld.DocumentLoader
	VDR             vdrapi.Registry
}

type Service struct {
	vcStatusManager vcStatusManager
	documentLoader  ld.DocumentLoader
	vdr             vdrapi.Registry
}

func New(config *Config) *Service {
	return &Service{
		vcStatusManager: config.VcStatusManager,
		documentLoader:  config.DocumentLoader,
		vdr:             config.VDR,
	}
}

func (s *Service) VerifyCredential(credential *verifiable.Credential, opts *Options,
	profile *verifier.Profile) ([]CredentialsVerificationCheckResult, error) {
	checks := profile.Checks.Credential

	var result []CredentialsVerificationCheckResult

	if checks.Proof {
		vcBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, fmt.Errorf("unexpected error on credential marshal: %w", err)
		}

		err = s.validateCredentialProof(vcBytes, opts, false)
		if err != nil {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "proof",
				Error: err.Error(),
			})
		}
	}
	if checks.Status {
		ver, err := s.checkVCStatus(credential.Status, credential.Issuer.ID)

		if err != nil {
			return nil, fmt.Errorf("failed to fetch the status : %w", err)
		}

		if !ver.Verified {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "credentialStatus",
				Error: ver.Message,
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

func (s *Service) validateCredentialProof(vcByte []byte, opts *Options, vcInVPValidation bool) error { // nolint: lll,gocyclo
	credential, err := s.parseAndVerifyVCStrictMode(vcByte)
	if err != nil {
		return fmt.Errorf("verifiable credential proof validation error : %w", err)
	}

	if len(credential.Proofs) == 0 {
		return errors.New("verifiable credential doesn't contains proof")
	}

	// TODO https://github.com/trustbloc/vcs/issues/412 figure out the process when vc has more than one proof
	proof := credential.Proofs[0]

	if !vcInVPValidation {
		// validate challenge
		if validateErr := validateProofData(proof, challenge, opts.Challenge); validateErr != nil {
			return validateErr
		}

		// validate domain
		if validateErr := validateProofData(proof, domain, opts.Domain); validateErr != nil {
			return validateErr
		}
	}

	// get the verification method
	verificationMethod, err := getVerificationMethodFromProof(proof)
	if err != nil {
		return err
	}

	// get the did doc from verification method
	didDoc, err := getDIDDocFromProof(verificationMethod, s.vdr)
	if err != nil {
		return err
	}

	// validate if issuer matches the controller of verification method
	if credential.Issuer.ID != didDoc.ID {
		return fmt.Errorf("controller of verification method doesn't match the issuer")
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, verificationMethod, didDoc); err != nil {
		return fmt.Errorf("verifiable credential proof purpose validation error : %w", err)
	}

	return nil
}

func (s *Service) checkVCStatus(vcStatus *verifiable.TypedID, issuer string) (*VerificationStatus, error) {
	vcResp := &VerificationStatus{
		Verified: false, Message: "Revoked",
	}

	// validate vc status
	if err := s.validateVCStatus(vcStatus); err != nil {
		return nil, err
	}

	statusListIndex, err := strconv.Atoi(vcStatus.CustomFields[csl.StatusListIndex].(string))
	if err != nil {
		return nil, err
	}

	revocationListVC, err := s.vcStatusManager.GetRevocationListVC(
		vcStatus.CustomFields[csl.StatusListCredential].(string))
	if err != nil {
		return nil, err
	}

	if revocationListVC.Issuer.ID != issuer {
		return nil, fmt.Errorf("issuer of the credential do not match vc revocation list issuer")
	}

	credSubject, ok := revocationListVC.Subject.([]verifiable.Subject)
	if !ok {
		return nil, fmt.Errorf("invalid subject field structure")
	}

	if credSubject[0].CustomFields[csl.StatusPurpose].(string) != vcStatus.CustomFields[csl.StatusPurpose].(string) {
		return nil, fmt.Errorf("vc statusPurpose not matching statusListCredential statusPurpose")
	}

	bitString, err := utils.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode bits: %w", err)
	}

	bitSet, err := bitString.Get(statusListIndex)
	if err != nil {
		return nil, err
	}

	if !bitSet {
		vcResp.Verified = true
		vcResp.Message = successMsg
	}

	return vcResp, nil
}

func (s *Service) validateVCStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != csl.StatusList2021Entry {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[csl.StatusListIndex] == nil {
		return fmt.Errorf("statusListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[csl.StatusListCredential] == nil {
		return fmt.Errorf("statusListCredential field not exist in vc status")
	}

	if vcStatus.CustomFields[csl.StatusPurpose] == nil {
		return fmt.Errorf("statusPurpose field not exist in vc status")
	}

	return nil
}

func validateProofData(proof verifiable.Proof, key, expectedValue string) error {
	actualVal := ""

	val, ok := proof[key]
	if ok {
		actualVal, _ = val.(string) // nolint
	}

	if expectedValue != actualVal {
		return fmt.Errorf("invalid %s in the proof : expected=%s actual=%s", key, expectedValue, actualVal)
	}

	return nil
}

func validateProofPurpose(proof verifiable.Proof, verificationMethod string, didDoc *did.Doc) error {
	purposeVal, ok := proof[proofPurpose]
	if !ok {
		return errors.New("proof doesn't have purpose")
	}

	purpose, ok := purposeVal.(string)
	if !ok {
		return errors.New("proof purpose is not a string")
	}

	return crypto.ValidateProofPurpose(purpose, verificationMethod, didDoc)
}

func getVerificationMethodFromProof(proof verifiable.Proof) (string, error) {
	verificationMethodVal, ok := proof[verificationMethod]
	if !ok {
		return "", errors.New("proof doesn't have verification method")
	}

	verificationMethod, ok := verificationMethodVal.(string)
	if !ok {
		return "", errors.New("proof verification method is not a string")
	}

	return verificationMethod, nil
}

func getDIDDocFromProof(verificationMethod string, vdr vdrapi.Registry) (*did.Doc, error) {
	didID, err := diddoc.GetDIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, err
	}

	docResolution, err := vdr.Resolve(didID)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
}
