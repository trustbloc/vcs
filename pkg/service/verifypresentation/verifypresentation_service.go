/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package verifypresentation -source=verifypresentation_service.go -mock_names vcVerifier=MockVcVerifier

package verifypresentation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hyperledger/aries-framework-go/pkg/common/utils"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	json2 "github.com/hyperledger/aries-framework-go/pkg/doc/util/json"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const (
	typeKey = "type"
	sdKey   = "_sd"
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
) ([]PresentationVerificationCheckResult, error) {
	startTime := time.Now().UTC()
	defer func() {
		logger.Debug("VerifyPresentation", log.WithDuration(time.Since(startTime)))
	}()
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

		logger.Debug(fmt.Sprintf("Checks.Presentation.Proof took %v", time.Since(st)))
	}

	if profile.Checks.Credential.CredentialExpiry {
		err := s.checkCredentialExpiry(lazyCredentials)
		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialExpiry",
				Error: err.Error(),
			})
		}
	}

	if profile.Checks.Credential.Strict {
		st := time.Now()

		err := s.checkCredentialStrict(lazyCredentials)
		if err != nil {
			logger.Error(fmt.Sprintf("NEW VALIDATION RETURNED ERROR %v", err))
		}
		err = s.checkCredentialStrict2(lazyCredentials)
		if err != nil {
			logger.Error(fmt.Sprintf("OLD VALIDATION RETURNED ERROR %v", err))
		}

		if err != nil {
			result = append(result, PresentationVerificationCheckResult{
				Check: "credentialStrict",
				Error: err.Error(),
			})
		}

		logger.Debug(fmt.Sprintf("Checks.Credential.Strict took %v", time.Since(st)))
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

		logger.Debug(fmt.Sprintf("Checks.Credential.Proof took %v", time.Since(st)))
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
		logger.Debug(fmt.Sprintf("Checks.Credential.Status took %v", time.Since(st)))
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
		logger.Debug(fmt.Sprintf("Checks.Credential.LinkedDomain took %v", time.Since(st)))
	}

	return result, nil
}

func (s *Service) checkCredentialStrict2(lazy []*LazyCredential) error { //nolint:gocognit
	for _, input := range lazy {
		cred, ok := input.Raw().(*verifiable.Credential)
		if !ok {
			logger.Warn(fmt.Sprintf("can not validate expiry. unexpected type %v",
				reflect.TypeOf(input).String()))
			return nil
		}

		displayCredential, err := cred.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		if err != nil {
			return err
		}

		bytes, err := displayCredential.MarshalJSON()
		if err != nil {
			return err
		}

		r, err := json2.ToMap(bytes)
		if err != nil {
			return err
		}

		logger.Debug(fmt.Sprintf("OLD. spew cred before %v", spew.Sdump(cred)))
		logger.Debug(fmt.Sprintf("OLD. spew cred after %v", spew.Sdump(displayCredential)))
		logger.Debug(fmt.Sprintf("OLD. spew2 %v", string(bytes)))
		logger.Debug(fmt.Sprintf("OLD. strict validation check %v", spew.Sdump(r)))

		if err := jsonld.ValidateJSONLDMap(r,
			jsonld.WithDocumentLoader(s.documentLoader),
			jsonld.WithStrictValidation(true),
		); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) checkCredentialStrict(lazy []*LazyCredential) error { //nolint:gocognit
	for _, input := range lazy {
		cred2, ok := input.Raw().(*verifiable.Credential)
		if !ok {
			logger.Warn(fmt.Sprintf("can not validate expiry. unexpected type %v",
				reflect.TypeOf(input).String()))
			return nil
		}

		displayCredential, err := cred2.CreateDisplayCredential(verifiable.DisplayAllDisclosures())
		if err != nil {
			return err
		}

		data := map[string]interface{}{}

		var ctx []interface{}
		for _, ct := range displayCredential.Context {
			ctx = append(ctx, ct)
		}

		var types []interface{}
		for _, t := range displayCredential.Types {
			types = append(types, t)
		}

		var claimsKeys []string
		if sub, ok := displayCredential.Subject.(verifiable.Subject); ok {
			types, claimsKeys, data = s.handleSubject(sub, types, data, claimsKeys)
		}

		if sub, ok := displayCredential.Subject.([]verifiable.Subject); ok {
			for _, subSub := range sub {
				types, claimsKeys, data = s.handleSubject(subSub, types, data, claimsKeys)
			}
		}

		for _, d := range displayCredential.SDJWTDisclosures {
			if d.Name == sdKey {
				continue
			}
			if d.Name == typeKey || d.Name == "@type" {
				if parsed := s.handleTypeParam(d.Value); len(parsed) > 0 {
					types = append(types, parsed...)
				}

				continue
			}

			if v := s.checkValue(d.Value); v != nil {
				data[d.Name] = v
				claimsKeys = append(claimsKeys, d.Name)
			}
		}

		data["@context"] = ctx
		data[typeKey] = types

		logger.Debug("strict validation check",
			logfields.WithClaimKeys(claimsKeys),
			logfields.WithCredentialID(displayCredential.ID),
		)

		j, _ := json.Marshal(data)
		logger.Debug(fmt.Sprintf("NEW. spew old raw %v", spew.Sdump(cred2)))
		logger.Debug(fmt.Sprintf("NEW. spew new raw %v", spew.Sdump(displayCredential)))
		logger.Debug(fmt.Sprintf("NEW. spew2 %v", string(j)))
		logger.Debug(fmt.Sprintf("NEW. strict validation check %v", spew.Sdump(data)))

		if err := jsonld.ValidateJSONLDMap(data,
			jsonld.WithDocumentLoader(s.documentLoader),
			jsonld.WithStrictValidation(true),
		); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) checkValue(data interface{}) interface{} {
	v, ok := data.(map[string]interface{})
	if !ok {
		return data
	}

	if len(v) == 0 {
		return nil
	}

	_, ok = v[sdKey]
	if !ok { // we are ok, no need to clear the map
		return data
	}

	mp := utils.CopyMap(v)
	delete(mp, sdKey)
	if len(mp) == 0 {
		return nil
	}

	return mp
}

func (s *Service) handleSubject(
	sub verifiable.Subject,
	types []interface{},
	data map[string]interface{},
	claimsKeys []string,
) ([]interface{}, []string, map[string]interface{}) {
	for k, v := range sub.CustomFields {
		if k == sdKey {
			continue
		}
		if k == typeKey || k == "@type" {
			if parsed := s.handleTypeParam(v); len(parsed) > 0 {
				types = append(types, parsed...)
			}

			continue
		}

		if v2 := s.checkValue(v); v2 != nil {
			data[k] = v2
			claimsKeys = append(claimsKeys, k)
		}
	}

	return types, claimsKeys, data
}

func (s *Service) handleTypeParam(input interface{}) []interface{} {
	var types []interface{}

	if v1, ok1 := input.(string); ok1 {
		types = append(types, v1)

		return types
	}

	if reflect.TypeOf(input).Kind() == reflect.Slice {
		s := reflect.ValueOf(input)
		for i := 0; i < s.Len(); i++ {
			types = append(types, s.Index(i).Interface())
		}
	}

	return types
}

func (s *Service) checkCredentialExpiry(lazy []*LazyCredential) error {
	for _, input := range lazy {
		credential, ok := input.Raw().(*verifiable.Credential)
		if !ok {
			logger.Warn(fmt.Sprintf("can not validate expiry. unexpected type %v",
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

		err = s.vcVerifier.ValidateVCStatus(ctx, extractedType, issuer)
		if err != nil {
			return err
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
