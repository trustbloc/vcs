/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifypresentation -source=verifypresentation_service.go -mock_names vcVerifier=MockVcVerifier

package verifypresentation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/did-go/doc/ld/validator"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type vcVerifier interface {
	ValidateCredentialProof(ctx context.Context, vc *verifiable.Credential, proofChallenge, proofDomain string, vcInVPValidation, strictValidation bool) error //nolint:lll
	ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer *verifiable.Issuer) error
	ValidateLinkedDomain(ctx context.Context, signingDID string) error
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
	claimKeys      map[string][]string
}

func New(config *Config) *Service {
	return &Service{
		vdr:            config.VDR,
		documentLoader: config.DocumentLoader,
		vcVerifier:     config.VcVerifier,
		claimKeys:      map[string][]string{},
	}
}

var logger = log.New("verify-presentation")

func (s *Service) VerifyPresentation( //nolint:funlen,gocognit
	ctx context.Context,
	presentation *verifiable.Presentation,
	opts *Options,
	profile *profileapi.Verifier,
) ([]PresentationVerificationCheckResult, error) {
	startTime := time.Now().UTC()
	defer func() {
		logger.Debugc(ctx, "VerifyPresentation", log.WithDuration(time.Since(startTime)))
	}()

	s.claimKeys = map[string][]string{}

	var result []PresentationVerificationCheckResult

	var credentials []*verifiable.Credential
	if presentation != nil {
		credentials = presentation.Credentials()
	}

	var targetPresentation interface{}
	targetPresentation = presentation

	if profile.Checks.Presentation.Proof {
		st := time.Now()

		if presentation.JWT != "" {
			targetPresentation = []byte(presentation.JWT)
		}

		err := s.validatePresentationProof(targetPresentation, opts)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "proof",
				Error: err.Error(),
			})
		}

		logger.Debugc(ctx, "Checks.Presentation.Proof", log.WithDuration(time.Since(st)))
	}

	if len(profile.Checks.Credential.IssuerTrustList) > 0 {
		err := s.checkIssuerTrustList(ctx, credentials, profile.Checks.Credential.IssuerTrustList)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "issuerTrustList",
				Error: err.Error(),
			})
		}
	}
	if profile.Checks.Credential.CredentialExpiry {
		err := s.checkCredentialExpiry(ctx, credentials)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialExpiry",
				Error: err.Error(),
			})
		}
	}

	if profile.Checks.Credential.Proof {
		st := time.Now()

		err := s.validateCredentialsProof(ctx, presentation.JWT, credentials)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialProof",
				Error: err.Error(),
			})
		}

		logger.Debugc(ctx, "Checks.Credential.Proof", log.WithDuration(time.Since(st)))
	}

	if profile.Checks.Credential.Status {
		st := time.Now()
		err := s.validateCredentialsStatus(ctx, credentials)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialStatus",
				Error: err.Error(),
			})
		}

		logger.Debugc(ctx, "Checks.Credential.Status", log.WithDuration(time.Since(st)))
	}

	if profile.Checks.Credential.LinkedDomain {
		st := time.Now()
		err := s.vcVerifier.ValidateLinkedDomain(ctx, profile.SigningDID.DID)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "linkedDomain",
				Error: err.Error(),
			})
		}
		logger.Debugc(ctx, "Checks.Credential.LinkedDomain", log.WithDuration(time.Since(st)))
	}

	if profile.Checks.Credential.Strict {
		st := time.Now()

		err := s.checkCredentialStrict(ctx, credentials)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialStrict",
				Error: err.Error(),
			})
		}
		logger.Debugc(ctx, "Checks.Credential.Strict", log.WithDuration(time.Since(st)))
	}

	return result, nil
}

func (s *Service) checkCredentialStrict(
	ctx context.Context, credentials []*verifiable.Credential) error { //nolint:gocognit
	for _, cred := range credentials {
		//TODO: check how bug fixed will affects other code.
		// previously if credential was not in format of *verifiable.Credential validations was ignored
		// This happened for all json-ld credentials in verifiable.Presentation

		credContents := cred.Contents()

		var credMap map[string]interface{}
		var err error

		if credContents.SDJWTHashAlg != nil {
			credMap, err = cred.CreateDisplayCredentialMap(verifiable.DisplayAllDisclosures())
			if err != nil {
				return err
			}
		} else {
			credMap = cred.ToRawJSON()
		}

		var claimKeys []string

		m, ok := credMap["credentialSubject"].(map[string]interface{})
		if ok {
			for k := range m {
				claimKeys = append(claimKeys, k)
			}
		}

		s.claimKeys[credContents.ID] = claimKeys

		if logger.IsEnabled(log.DEBUG) {
			logger.Debugc(ctx, "verifier strict validation check",
				logfields.WithClaimKeys(claimKeys),
				logfields.WithCredentialID(credContents.ID),
			)
		}

		if err = validator.ValidateJSONLDMap(credMap,
			validator.WithDocumentLoader(s.documentLoader),
			validator.WithStrictValidation(true),
		); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) checkCredentialExpiry(_ context.Context, credentials []*verifiable.Credential) error {
	for _, credential := range credentials {
		vcc := credential.Contents()
		if vcc.Expired != nil && time.Now().UTC().After(vcc.Expired.Time) {
			return errors.New("credential expired")
		}
	}

	return nil
}

func (s *Service) checkIssuerTrustList(
	_ context.Context,
	credentials []*verifiable.Credential,
	trustList map[string]profileapi.TrustList,
) error {
	for _, cred := range credentials {
		var issuerID string
		var credTypes []string

		if cred.Contents().Issuer != nil {
			issuerID = cred.Contents().Issuer.ID
		}
		credTypes = cred.Contents().Types

		var finalCredType string
		if len(credTypes) > 0 {
			finalCredType = credTypes[len(credTypes)-1]
		}

		cfg, ok := trustList[issuerID]
		if !ok {
			return fmt.Errorf("issuer with id: %v is not a member of trustlist", issuerID)
		}

		if len(cfg.CredentialTypes) == 0 { // we are trusting to all credential types
			continue
		}

		if !lo.Contains(cfg.CredentialTypes, finalCredType) {
			return fmt.Errorf("credential type: %v is not a member of trustlist configuration", finalCredType)
		}
	}

	return nil
}

func (s *Service) validatePresentationProof(targetPresentation interface{}, opts *Options) error {
	var final *verifiable.Presentation
	switch pres := targetPresentation.(type) {
	case *verifiable.Presentation:
		final = pres
	case []byte:
		vp, err := verifiable.ParsePresentation(
			pres,
			verifiable.WithPresPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
			),
			verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
		)
		if err != nil {
			return fmt.Errorf("verifiable presentation proof validation error : %w", err)
		}
		final = vp
	}
	if final.JWT == "" {
		return s.validateProofData(final, opts)
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

func (s *Service) validateCredentialsProof(
	ctx context.Context,
	vpJWT string,
	credentials []*verifiable.Credential,
) error {
	for _, cred := range credentials {
		err := s.vcVerifier.ValidateCredentialProof(ctx, cred, "", "", true, vpJWT == "")
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) validateCredentialsStatus(
	ctx context.Context,
	credentials []*verifiable.Credential,
) error {
	for _, cred := range credentials {
		extractedType, issuer := s.extractCredentialStatus(cred)

		if extractedType != nil {
			err := s.vcVerifier.ValidateVCStatus(ctx, extractedType, issuer)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Service) extractCredentialStatus(
	cred *verifiable.Credential) (*verifiable.TypedID, *verifiable.Issuer) {
	if cred == nil {
		return nil, nil
	}

	credContents := cred.Contents()

	return credContents.Status, credContents.Issuer
}

// GetClaimKeys returns credential claim keys.
func (s *Service) GetClaimKeys() map[string][]string {
	return s.claimKeys
}
