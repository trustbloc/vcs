/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifypresentation -source=verifypresentation_service.go -mock_names vcVerifier=MockVcVerifier,trustRegistryService=MockTrustRegistryService

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
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"

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
	VDR                   vdrapi.Registry
	DocumentLoader        ld.DocumentLoader
	VcVerifier            vcVerifier
	DataIntegrityVerifier *dataintegrity.Verifier
}

type Service struct {
	vdr                   vdrapi.Registry
	documentLoader        ld.DocumentLoader
	vcVerifier            vcVerifier
	dataIntegrityVerifier *dataintegrity.Verifier
}

func New(config *Config) *Service {
	return &Service{
		vdr:            config.VDR,
		documentLoader: config.DocumentLoader,
		vcVerifier:     config.VcVerifier,
	}
}

var logger = log.New("verify-presentation")

func (s *Service) VerifyPresentation( //nolint:funlen,gocognit
	ctx context.Context,
	presentation *verifiable.Presentation,
	opts *Options,
	profile *profileapi.Verifier,
) (PresentationVerificationResult, map[string][]string, error) {
	startTime := time.Now().UTC()
	defer func() {
		logger.Debugc(ctx, "VerifyPresentation", log.WithDuration(time.Since(startTime)))
	}()

	result := &PresentationVerificationResult{}

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
		result.Checks = append(result.Checks, &Check{
			Check: "proof",
			Error: err,
		})

		logger.Debugc(ctx, "Checks.Presentation.Proof", log.WithDuration(time.Since(st)))
	}

	for _, cred := range credentials { // vc-suite requirement
		content := cred.Contents()

		var err error

		if len(content.Types) == 0 {
			err = errors.New("credential type is missing")
		}

		result.Checks = append(result.Checks, &Check{
			Check: "credentialType",
			Error: err,
		})

		err = nil

		if content.Issued != nil && content.Expired != nil {
			if content.Issued.After(content.Expired.Time) || content.Issued.Equal(content.Expired.Time) {
				err = errors.New("credential issued date should be before expired date")
			}

			result.Checks = append(result.Checks, &Check{
				Check: "credentialExpiry",
				Error: err,
			})
		}
	}

	if len(profile.Checks.Credential.IssuerTrustList) > 0 {
		err := s.checkIssuerTrustList(ctx, credentials, profile.Checks.Credential.IssuerTrustList)

		result.Checks = append(result.Checks, &Check{
			Check: "issuerTrustList",
			Error: err,
		})
	}

	if profile.Checks.Credential.CredentialExpiry {
		err := s.checkCredentialExpiry(credentials)

		result.Checks = append(result.Checks, &Check{
			Check: "credentialExpiry",
			Error: err,
		})
	}

	if profile.Checks.Credential.Proof {
		st := time.Now()

		err := s.validateCredentialsProof(ctx, presentation.JWT, credentials)
		result.Checks = append(result.Checks, &Check{
			Check: "credentialProof",
			Error: err,
		})

		logger.Debugc(ctx, "Checks.Credential.Proof", log.WithDuration(time.Since(st)))
	}

	if profile.Checks.Credential.Status {
		st := time.Now()

		err := s.validateCredentialsStatus(ctx, credentials)
		result.Checks = append(result.Checks, &Check{
			Check: "credentialStatus",
			Error: err,
		})

		logger.Debugc(ctx, "Checks.Credential.Status", log.WithDuration(time.Since(st)))
	}

	if profile.Checks.Credential.LinkedDomain {
		st := time.Now()

		err := s.checkLinkedDomain(ctx, credentials)

		result.Checks = append(result.Checks, &Check{
			Check: "linkedDomain",
			Error: err,
		})

		logger.Debugc(ctx, "Checks.Credential.LinkedDomain", log.WithDuration(time.Since(st)))
	}

	var claimsKeys map[string][]string
	if profile.Checks.Credential.Strict {
		st := time.Now()

		keys, err := s.checkCredentialStrict(ctx, credentials)
		claimsKeys = keys

		result.Checks = append(result.Checks, &Check{
			Check: "credentialStrict",
			Error: err,
		})

		logger.Debugc(ctx, "Checks.Credential.Strict", log.WithDuration(time.Since(st)))
	}

	return *result, claimsKeys, nil
}

func (s *Service) checkCredentialStrict(
	ctx context.Context,
	credentials []*verifiable.Credential,
) (map[string][]string, error) { //nolint:gocognit
	claimKeysDict := map[string][]string{}

	for _, cred := range credentials {
		// TODO: check how bug fixed will affects other code.
		// previously if credential was not in format of *verifiable.Credential validations was ignored
		// This happened for all json-ld credentials in verifiable.Presentation

		credContents := cred.Contents()

		var credMap map[string]interface{}
		var err error

		if credContents.SDJWTHashAlg != nil {
			credMap, err = cred.CreateDisplayCredentialMap(verifiable.DisplayAllDisclosures())
			if err != nil {
				return claimKeysDict, err
			}
		} else {
			credMap = cred.ToRawJSON()
		}

		var claimKeys []string
		m, ok := credMap["credentialSubject"].(map[string]interface{})
		if ok {
			for k := range m {
				claimKeysDict[credContents.ID] = append(claimKeysDict[credContents.ID], k)
				claimKeys = append(claimKeys, k)
			}
		}

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
			return claimKeysDict, err
		}
	}

	return claimKeysDict, nil
}

func (s *Service) checkCredentialExpiry(credentials []*verifiable.Credential) error {
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

func (s *Service) checkLinkedDomain(ctx context.Context, credentials []*verifiable.Credential) error {
	for _, cred := range credentials {
		var issuerID string

		if cred.Contents().Issuer != nil {
			issuerID = cred.Contents().Issuer.ID
		}

		if err := s.vcVerifier.ValidateLinkedDomain(ctx, issuerID); err != nil {
			return err
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
		presOpts := []verifiable.PresentationOpt{
			verifiable.WithPresProofChecker(
				defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(s.vdr)),
			),
			verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
		}

		if s.dataIntegrityVerifier != nil {
			presOpts = append(presOpts, verifiable.WithPresDataIntegrityVerifier(s.dataIntegrityVerifier))
		}

		vp, err := verifiable.ParsePresentation(
			pres,
			presOpts...,
		)
		if err != nil {
			return fmt.Errorf("verifiable presentation proof validation error : %w", err)
		}
		final = vp
	}
	if final.JWT == "" && final.CWT == nil {
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
	chans := make([]chan error, 0)

	for _, credElement := range credentials {
		cred := credElement
		ch := make(chan error)
		chans = append(chans, ch)

		go func() {
			defer close(ch)

			ch <- s.vcVerifier.ValidateCredentialProof(ctx, cred, "", "", true, vpJWT == "")
		}()
	}

	var finalErr error
	for _, ch := range chans {
		if err := <-ch; err != nil {
			finalErr = errors.Join(finalErr, err)
		}
	}

	return finalErr
}

func (s *Service) validateCredentialsStatus(
	ctx context.Context,
	credentials []*verifiable.Credential,
) error {
	var chArr []chan error

	for _, credItem := range credentials {
		cred := credItem
		ch := make(chan error)
		chArr = append(chArr, ch)

		go func() {
			defer close(ch)
			typedID, issuer := s.extractCredentialStatus(cred)

			if typedID != nil {
				ch <- s.vcVerifier.ValidateVCStatus(ctx, typedID, issuer)
			}
		}()
	}

	for _, ch := range chArr {
		if err := <-ch; err != nil {
			return err
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
