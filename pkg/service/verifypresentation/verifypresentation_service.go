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
	"reflect"
	"time"

	"github.com/hyperledger/aries-framework-go/component/models/ld/validator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	jsonutil "github.com/hyperledger/aries-framework-go/pkg/doc/util/json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type vcVerifier interface {
	ValidateCredentialProof(ctx context.Context, vcByte []byte, proofChallenge, proofDomain string, vcInVPValidation, isJWT bool) error //nolint:lll
	ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer string) error
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

	var lazyCredentials []*LazyCredential
	if presentation != nil {
		for _, c := range presentation.Credentials() {
			lazyCredentials = append(lazyCredentials, NewLazyCredential(c))
		}
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

	if profile.Checks.Credential.CredentialExpiry {
		err := s.checkCredentialExpiry(ctx, lazyCredentials)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialExpiry",
				Error: err.Error(),
			})
		}
	}

	if profile.Checks.Credential.Proof {
		st := time.Now()

		err := s.validateCredentialsProof(ctx, presentation.JWT, lazyCredentials)
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
		err := s.validateCredentialsStatus(ctx, lazyCredentials)
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

		err := s.checkCredentialStrict(ctx, lazyCredentials)
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

func (s *Service) checkCredentialStrict(ctx context.Context, lazy []*LazyCredential) error { //nolint:gocognit
	for _, input := range lazy {
		cred, ok := input.Raw().(*verifiable.Credential)
		if !ok {
			logger.Warnc(ctx, fmt.Sprintf("can not validate strict. unexpected type %v",
				reflect.TypeOf(input).String()))
			return nil
		}

		var credMap map[string]interface{}
		var err error

		if cred.SDJWTHashAlg != "" {
			credMap, err = cred.CreateDisplayCredentialMap(verifiable.DisplayAllDisclosures())
			if err != nil {
				return err
			}
		} else {
			cred.JWT = ""
			var credentialBytes []byte

			credentialBytes, err = cred.MarshalJSON()
			if err != nil {
				return fmt.Errorf("unable to marshal credential: %w", err)
			}

			credMap, err = jsonutil.ToMap(credentialBytes)
			if err != nil {
				return err
			}
		}

		var claimKeys []string

		m, ok := credMap["credentialSubject"].(map[string]interface{})
		if ok {
			for k := range m {
				claimKeys = append(claimKeys, k)
			}
		}

		s.claimKeys[cred.ID] = claimKeys

		if logger.IsEnabled(log.DEBUG) {
			logger.Debugc(ctx, "verifier strict validation check",
				logfields.WithClaimKeys(claimKeys),
				logfields.WithCredentialID(cred.ID),
			)
		}

		if err = validator.ValidateJSONLDMap(credMap,
			jsonld.WithDocumentLoader(s.documentLoader),
			jsonld.WithStrictValidation(true),
		); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) checkCredentialExpiry(ctx context.Context, lazy []*LazyCredential) error {
	for _, input := range lazy {
		credential, ok := input.Raw().(*verifiable.Credential)
		if !ok {
			logger.Warnc(ctx, fmt.Sprintf("can not validate expiry. unexpected type %v",
				reflect.TypeOf(input).String()))
			return nil
		}
		if credential.Expired != nil && time.Now().UTC().After(credential.Expired.Time) {
			return errors.New("credential expired")
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
	credentials []*LazyCredential,
) error {
	for _, cred := range credentials {
		vcBytes, err := cred.Serialized()
		if err != nil {
			return err
		}

		err = s.vcVerifier.ValidateCredentialProof(ctx, vcBytes, "", "", true, vpJWT != "")
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) validateCredentialsStatus(
	ctx context.Context,
	credentials []*LazyCredential,
) error {
	for _, cred := range credentials {
		extractedType, issuer, err := s.extractCredentialStatus(cred)
		if err != nil {
			return err
		}

		if extractedType != nil {
			err = s.vcVerifier.ValidateVCStatus(ctx, extractedType, issuer)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Service) extractCredentialStatus(cred *LazyCredential) (*verifiable.TypedID, string, error) {
	if cred == nil {
		return nil, "", nil
	}

	if v, ok := cred.Raw().(*verifiable.Credential); ok {
		return v.Status, v.Issuer.ID, nil
	}

	v, ok := cred.Raw().(map[string]interface{})
	if !ok {
		return nil, "", fmt.Errorf("unsupported credential type %v", reflect.TypeOf(cred.Raw()).String())
	}

	var issuerID string
	switch issuerData := v["issuer"].(type) {
	case map[string]interface{}:
		issuerID = fmt.Sprint(issuerData["id"])
	case string:
		issuerID = issuerData
	}

	status, ok := v["credentialStatus"]
	if !ok {
		return nil, "", nil
	}

	statusMap, ok := status.(map[string]interface{})
	if !ok {
		return nil, "", fmt.Errorf("unsupported status list type type %v", reflect.TypeOf(status).String())
	}

	finalObj := &verifiable.TypedID{
		CustomFields: map[string]interface{}{},
	}
	for k, val := range statusMap {
		switch k {
		case "id":
			finalObj.ID = fmt.Sprint(val)
		case "type":
			finalObj.Type = fmt.Sprint(val)
		default:
			finalObj.CustomFields[k] = val
		}
	}

	return finalObj, issuerID, nil
}

// GetClaimKeys returns credential claim keys.
func (s *Service) GetClaimKeys() map[string][]string {
	return s.claimKeys
}
