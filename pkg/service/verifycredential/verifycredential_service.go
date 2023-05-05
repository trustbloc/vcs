/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifycredential -source=verifycredential_service.go -mock_names statusListVCURIResolver=MockStatusListVCResolver

package verifycredential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const (
	revokedMsg = "revoked"
)

type statusListVCURIResolver interface {
	Resolve(ctx context.Context, statusListVCURL string) (*verifiable.Credential, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	VCStatusProcessorGetter vc.StatusProcessorGetter
	StatusListVCResolver    statusListVCURIResolver
	DocumentLoader          ld.DocumentLoader
	VDR                     vdrapi.Registry
	HTTPClient              httpClient
}

type Service struct {
	vcStatusProcessorGetter vc.StatusProcessorGetter
	statusListVCURIResolver statusListVCURIResolver
	documentLoader          ld.DocumentLoader
	vdr                     vdrapi.Registry
	httpClient              httpClient
}

func New(config *Config) *Service {
	return &Service{
		statusListVCURIResolver: config.StatusListVCResolver,
		vcStatusProcessorGetter: config.VCStatusProcessorGetter,
		documentLoader:          config.DocumentLoader,
		vdr:                     config.VDR,
		httpClient:              config.HTTPClient,
	}
}

func (s *Service) VerifyCredential(ctx context.Context, credential *verifiable.Credential, opts *Options,
	profile *profileapi.Verifier) ([]CredentialsVerificationCheckResult, error) {
	checks := profile.Checks.Credential

	var result []CredentialsVerificationCheckResult

	if checks.LinkedDomain {
		if err := s.ValidateLinkedDomain(ctx, profile.SigningDID.DID); err != nil {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "linkedDomain",
				Error: err.Error(),
			})
		}
	}
	if checks.Proof {
		vcBytes, err := json.Marshal(credential)
		if err != nil {
			return nil, fmt.Errorf("unexpected error on credential marshal: %w", err)
		}

		err = s.ValidateCredentialProof(ctx, vcBytes, opts.Challenge, opts.Domain, false, credential.JWT != "")
		if err != nil {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "proof",
				Error: err.Error(),
			})
		}
	}
	if checks.Status {
		if credential.Status == nil {
			return nil, fmt.Errorf("vc missing status list field")
		}

		err := s.ValidateVCStatus(ctx, credential.Status, credential.Issuer.ID)
		if err != nil {
			result = append(result, CredentialsVerificationCheckResult{
				Check: "credentialStatus",
				Error: err.Error(),
			})
		}
	}

	return result, nil
}

func (s *Service) parseAndVerifyVC(vcBytes []byte, isJWT bool) (*verifiable.Credential, error) {
	opts := []verifiable.CredentialOpt{
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	}

	if !isJWT {
		opts = append(opts, verifiable.WithStrictValidation())
	}

	cred, err := verifiable.ParseCredential(
		vcBytes,
		opts...,
	)
	return cred, err
}

// ValidateCredentialProof validate credential proof.
func (s *Service) ValidateCredentialProof(ctx context.Context, vcByte []byte, proofChallenge, proofDomain string,
	vcInVPValidation, isJWT bool) error { // nolint: lll,gocyclo
	credential, err := s.parseAndVerifyVC(vcByte, isJWT)
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

func (s *Service) ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer string) error {
	vcStatusProcessor, err := s.vcStatusProcessorGetter(vc.StatusType(vcStatus.Type))
	if err != nil {
		return err
	}

	if err = vcStatusProcessor.ValidateStatus(vcStatus); err != nil {
		return err
	}

	statusListIndex, err := vcStatusProcessor.GetStatusListIndex(vcStatus)
	if err != nil {
		return err
	}

	statusVCURL, err := vcStatusProcessor.GetStatusVCURI(vcStatus)
	if err != nil {
		return err
	}

	statusListVC, err := s.statusListVCURIResolver.Resolve(ctx, statusVCURL)
	if err != nil {
		return err
	}

	if statusListVC.Issuer.ID != issuer {
		return fmt.Errorf("issuer of the credential do not match status list vc issuer")
	}

	credSubject, ok := statusListVC.Subject.([]verifiable.Subject)
	if !ok {
		return fmt.Errorf("invalid subject field structure")
	}

	bitString, err := bitstring.DecodeBits(credSubject[0].CustomFields["encodedList"].(string))
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
