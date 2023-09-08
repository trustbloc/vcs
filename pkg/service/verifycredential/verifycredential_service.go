/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifycredential -source=verifycredential_service.go -mock_names statusListVCURIResolver=MockStatusListVCResolver,kmsRegistry=MockKMSRegistry

package verifycredential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/piprate/json-gold/ld"

	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/verifiable"

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
	diVerifier, err := s.getDataIntegrityVerifier()
	if err != nil {
		return nil, fmt.Errorf("get data integrity verifier: %w", err)
	}

	opts := []verifiable.CredentialOpt{
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
		verifiable.WithDataIntegrityVerifier(diVerifier),
		// Use empty domain and challenge in order to skip the validation.
		// See usage of vcInVPValidation variable in ValidateCredentialProof method.
		// TODO: define verifier purpose field.
		verifiable.WithExpectedDataIntegrityFields(crypto.Authentication, "", ""),
	}

	if !isJWT {
		opts = append(opts, verifiable.WithStrictValidation())
	}

	cred, err := verifiable.ParseCredential(vcBytes, opts...)
	if err != nil {
		return nil, fmt.Errorf("verifiable credential proof validation error : %w", err)
	}

	return cred, nil
}

// ValidateCredentialProof validate credential proof.
func (s *Service) ValidateCredentialProof(_ context.Context, vcByte []byte, proofChallenge, proofDomain string,
	vcInVPValidation, isJWT bool) error { // nolint: lll,gocyclo
	credential, err := s.parseAndVerifyVC(vcByte, isJWT)
	if err != nil {
		return err
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
	if err = crypto.ValidateProof(proof, verificationMethod, didDoc); err != nil {
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

func (s *Service) getDataIntegrityVerifier() (*dataintegrity.Verifier, error) {
	verifySuite := ecdsa2019.NewVerifierInitializer(&ecdsa2019.VerifierInitializerOptions{
		LDDocumentLoader: s.documentLoader,
	})

	verifier, err := dataintegrity.NewVerifier(&dataintegrity.Options{
		DIDResolver: s.vdr,
	}, verifySuite)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	return verifier, nil
}
