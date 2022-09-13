/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	commhttp "github.com/trustbloc/vcs/pkg/restapi/v0.1/internal/common/http"

	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/pkg/internal/common/diddoc"
	"github.com/trustbloc/vcs/pkg/internal/common/support"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
)

const (
	profileIDPathParam = "id"

	// Verifier endpoints.
	verifierBasePath                  = "/verifier"
	profileEndpoint                   = verifierBasePath + "/profile"
	getProfileEndpoint                = profileEndpoint + "/" + "{" + profileIDPathParam + "}"
	deleteProfileEndpoint             = profileEndpoint + "/" + "{" + profileIDPathParam + "}"
	credentialsVerificationEndpoint   = "/" + "{" + profileIDPathParam + "}" + verifierBasePath + "/credentials/verify"
	presentationsVerificationEndpoint = "/" + "{" + profileIDPathParam + "}" + verifierBasePath + "/presentations/verify"

	invalidRequestErrMsg = "Invalid request"

	successMsg = "success"

	// Credential verification checks.
	proofCheck  = "proof"
	statusCheck = "credentialStatus"

	// Proof data keys.
	challenge          = "challenge"
	domain             = "domain"
	proofPurpose       = "proofPurpose"
	verificationMethod = "verificationMethod"

	cslRequestTokenName = "csl"
)

var logger = log.New("vcs-verifier-restapi")

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// New returns CreateCredential instance.
func New(config *Config) (*Operation, error) {
	profileStore, err := config.StoreProvider.OpenVerifierProfileStore()
	if err != nil {
		return nil, err
	}

	svc := &Operation{
		profileStore:   profileStore,
		vdr:            config.VDRI,
		httpClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:  config.RequestTokens,
		documentLoader: config.DocumentLoader,
	}

	return svc, nil
}

// Config defines configuration for verifier operations.
type Config struct {
	StoreProvider  vcsstorage.Provider
	VDRI           vdrapi.Registry
	TLSConfig      *tls.Config
	RequestTokens  map[string]string
	DocumentLoader ld.DocumentLoader
}

// Operation defines handlers for verifier service.
type Operation struct {
	profileStore   vcsstorage.VerifierProfileStore
	vdr            vdrapi.Registry
	httpClient     httpClient
	requestTokens  map[string]string
	documentLoader ld.DocumentLoader
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		// profile
		support.NewHTTPHandler(profileEndpoint, http.MethodPost, o.createProfileHandler),
		support.NewHTTPHandler(getProfileEndpoint, http.MethodGet, o.getProfileHandler),
		support.NewHTTPHandler(deleteProfileEndpoint, http.MethodDelete, o.deleteProfileHandler),

		// verification
		support.NewHTTPHandler(credentialsVerificationEndpoint, http.MethodPost, o.verifyCredentialHandler),
		support.NewHTTPHandler(presentationsVerificationEndpoint, http.MethodPost, o.verifyPresentationHandler),
	}
}

// CreateProfile swagger:route POST /verifier/profile verifier profileData
//
// Creates verifier profile.
//
// Responses:
//    default: genericError
//        201: profileData
func (o *Operation) createProfileHandler(rw http.ResponseWriter, req *http.Request) {
	request := &vcsstorage.VerifierProfile{}

	if err := json.NewDecoder(req.Body).Decode(request); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	if err := validateProfileRequest(request); err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	_, err := o.profileStore.Get(request.ID)
	if err == nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("profile %s already exists", request.ID))

		return
	} else if !errors.Is(err, ariesstorage.ErrDataNotFound) {
		commhttp.WriteErrorResponse(rw, http.StatusInternalServerError, err.Error())

		return
	}

	err = o.profileStore.Put(*request)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusCreated, request)
}

// RetrieveProfile swagger:route GET /verifier/profile/{id} verifier getProfileReq
//
// Retrieves verifier profile.
//
// Responses:
//    default: genericError
//        200: profileData
func (o *Operation) getProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.Get(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}

	commhttp.WriteResponse(rw, http.StatusOK, profile)
}

// DeleteVerifierProfile swagger:route DELETE /verifier/profile/{id} verifier deleteProfileReq
//
// Deletes verifier profile.
//
// Responses:
// 		default: genericError
//			200: emptyRes
func (o *Operation) deleteProfileHandler(rw http.ResponseWriter, req *http.Request) {
	profileID := mux.Vars(req)["id"]

	err := o.profileStore.Delete(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, err.Error())

		return
	}
}

//nolint:funlen,gocyclo
// VerifyCredential swagger:route POST /{id}/verifier/credentials/verify verifier verifyCredentialReq
//
// Verifies a credential.
//
// Responses:
//    default: genericError
//        200: verifyCredentialSuccessResp
//        400: verifyCredentialFailureResp
func (o *Operation) verifyCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	// get the profile
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.Get(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid verifier profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	verificationReq := CredentialsVerificationRequest{}

	err = json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	vc, err := o.parseAndVerifyVC(verificationReq.Credential)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	checks := getCredentialChecks(&profile, verificationReq.Opts)

	var result []CredentialsVerificationCheckResult

	for _, val := range checks {
		switch val {
		case proofCheck:
			err := o.validateCredentialProof(verificationReq.Credential, verificationReq.Opts, false)
			if err != nil {
				result = append(result, CredentialsVerificationCheckResult{
					Check: val,
					Error: err.Error(),
				})
			}
		case statusCheck:
			failureMessage := ""

			ver, err := o.checkVCStatus(vc.Status, vc.Issuer.ID)

			if err != nil {
				failureMessage = fmt.Sprintf("failed to fetch the status : %s", err.Error())
			} else if !ver.Verified {
				failureMessage = ver.Message
			}

			if failureMessage != "" {
				result = append(result, CredentialsVerificationCheckResult{
					Check: val,
					Error: failureMessage,
				})
			}
		default:
			result = append(result, CredentialsVerificationCheckResult{
				Check: val,
				Error: "check not supported",
			})
		}
	}

	if len(result) == 0 {
		commhttp.WriteResponse(rw, http.StatusOK, &CredentialsVerificationSuccessResponse{
			Checks: checks,
		})
	} else {
		commhttp.WriteResponse(rw, http.StatusBadRequest, &CredentialsVerificationFailResponse{
			Checks: result,
		})
	}
}

// VerifyPresentation swagger:route POST /{id}/verifier/presentations/verify verifier verifyPresentationReq
//
// Verifies a presentation.
//
// Responses:
//    default: genericError
//        200: verifyPresentationSuccessResp
//        400: verifyPresentationFailureResp
func (o *Operation) verifyPresentationHandler(rw http.ResponseWriter, req *http.Request) {
	// get the profile
	profileID := mux.Vars(req)[profileIDPathParam]

	profile, err := o.profileStore.Get(profileID)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf("invalid verifier profile - id=%s: err=%s",
			profileID, err.Error()))

		return
	}

	// get the request
	verificationReq := VerifyPresentationRequest{}

	err = json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	checks := getPresentationChecks(&profile, verificationReq.Opts)

	var result []VerifyPresentationCheckResult

	for _, val := range checks {
		switch val {
		case proofCheck:
			err := o.validatePresentationProof(verificationReq.Presentation, verificationReq.Opts)
			if err != nil {
				result = append(result, VerifyPresentationCheckResult{
					Check: val,
					Error: err.Error(),
				})
			}
		case statusCheck:
			_, err := o.parseAndVerifyVP(verificationReq.Presentation, false, false, true)
			if err != nil {
				result = append(result, VerifyPresentationCheckResult{
					Check: val,
					Error: err.Error(),
				})
			}
		default:
			result = append(result, VerifyPresentationCheckResult{
				Check: val,
				Error: "check not supported",
			})
		}
	}

	if len(result) == 0 {
		commhttp.WriteResponse(rw, http.StatusOK, &VerifyPresentationSuccessResponse{
			Checks: checks,
		})
	} else {
		commhttp.WriteResponse(rw, http.StatusBadRequest, &VerifyPresentationFailureResponse{
			Checks: result,
		})
	}
}

func (o *Operation) validateCredentialProof(vcByte []byte, opts *CredentialsVerificationOptions, vcInVPValidation bool) error { // nolint: lll,gocyclo
	vc, err := o.parseAndVerifyVCStrictMode(vcByte)
	if err != nil {
		return fmt.Errorf("verifiable credential proof validation error : %w", err)
	}

	if len(vc.Proofs) == 0 {
		return errors.New("verifiable credential doesn't contains proof")
	}

	// validate proof challenge and domain
	if opts == nil {
		opts = &CredentialsVerificationOptions{}
	}

	// TODO https://github.com/trustbloc/vcs/issues/412 figure out the process when vc has more than one proof
	proof := vc.Proofs[0]

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
	didDoc, err := getDIDDocFromProof(verificationMethod, o.vdr)
	if err != nil {
		return err
	}

	// validate if issuer matches the controller of verification method
	if vc.Issuer.ID != didDoc.ID {
		return fmt.Errorf("controller of verification method doesn't match the issuer")
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, verificationMethod, didDoc); err != nil {
		return fmt.Errorf("verifiable credential proof purpose validation error : %w", err)
	}

	return nil
}

func (o *Operation) validatePresentationProof(vpByte []byte, opts *VerifyPresentationOptions) error { // nolint: gocyclo
	vp, err := o.parseAndVerifyVP(vpByte, true, true, false)
	if err != nil {
		return fmt.Errorf("verifiable presentation proof validation error : %w", err)
	}

	// validate proof challenge and domain
	if opts == nil {
		opts = &VerifyPresentationOptions{}
	}

	var proof verifiable.Proof

	// TODO https://github.com/trustbloc/vcs/issues/412 figure out the process when vc has more than one proof
	if len(vp.Proofs) != 0 {
		proof = vp.Proofs[0]
	}

	// validate challenge
	if validateErr := validateProofData(proof, challenge, opts.Challenge); validateErr != nil {
		return validateErr
	}

	// validate domain
	if validateErr := validateProofData(proof, domain, opts.Domain); validateErr != nil {
		return validateErr
	}

	// get the verification method
	verificationMethod, err := getVerificationMethodFromProof(proof)
	if err != nil {
		return err
	}

	// get the did doc from verification method
	didDoc, err := getDIDDocFromProof(verificationMethod, o.vdr)
	if err != nil {
		return err
	}

	// validate if holder matches the controller of verification method
	if vp.Holder != "" && vp.Holder != didDoc.ID {
		return fmt.Errorf("controller of verification method doesn't match the holder")
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, verificationMethod, didDoc); err != nil {
		return fmt.Errorf("verifiable presentation proof purpose validation error : %w", err)
	}

	return nil
}

func (o *Operation) validateVCStatus(vcStatus *verifiable.TypedID) error {
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

//nolint: gocyclo
func (o *Operation) checkVCStatus(vcStatus *verifiable.TypedID, issuer string) (*VerifyCredentialResponse, error) {
	vcResp := &VerifyCredentialResponse{
		Verified: false, Message: "Revoked",
	}

	// validate vc status
	if err := o.validateVCStatus(vcStatus); err != nil {
		return nil, err
	}

	statusListIndex, err := strconv.Atoi(vcStatus.CustomFields[csl.StatusListIndex].(string))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		vcStatus.CustomFields[csl.StatusListCredential].(string), nil)
	if err != nil {
		return nil, err
	}

	resp, err := o.sendHTTPRequest(req, http.StatusOK, o.requestTokens[cslRequestTokenName])
	if err != nil {
		return nil, err
	}

	revocationListVC, err := o.parseAndVerifyVC(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	if revocationListVC.Issuer.ID != issuer {
		return nil, fmt.Errorf("issuer of the credential do not match vc revocation list issuer")
	}

	credSubject, ok := revocationListVC.Subject.([]verifiable.Subject)
	if !ok {
		return nil, fmt.Errorf("")
	}

	if credSubject[0].CustomFields["statusPurpose"].(string) != vcStatus.CustomFields[csl.StatusPurpose].(string) {
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

func (o *Operation) parseAndVerifyVCStrictMode(vcBytes []byte) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(o.vdr).PublicKeyFetcher(),
		),
		verifiable.WithStrictValidation(),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader),
	)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(o.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(o.documentLoader),
	)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

//nolint:funlen,gocyclo,gocognit
func (o *Operation) parseAndVerifyVP(vpBytes []byte, validateVPPoof, validateCredentialProof,
	validateCredentialStatus bool) (*verifiable.Presentation, error) {
	var vp *verifiable.Presentation

	var err error

	if validateVPPoof {
		vp, err = verifiable.ParsePresentation(
			vpBytes,
			verifiable.WithPresPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(o.vdr).PublicKeyFetcher(),
			),
			verifiable.WithPresJSONLDDocumentLoader(o.documentLoader),
		)
		if err != nil {
			return nil, err
		}
	} else {
		vp, err = verifiable.ParsePresentation(vpBytes, verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(o.documentLoader))
		if err != nil {
			return nil, err
		}
	}

	// vp is verified

	// verify if the credentials in vp are valid
	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}

		if validateCredentialProof {
			// verify if the credential in vp is valid
			err = o.validateCredentialProof(vcBytes, nil, true)
			if err != nil {
				return nil, err
			}
		}

		if validateCredentialStatus {
			failureMessage := ""

			vc, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(),
				verifiable.WithJSONLDDocumentLoader(o.documentLoader))
			if err != nil {
				return nil, err
			}

			ver, err := o.checkVCStatus(vc.Status, vc.Issuer.ID)

			if err != nil {
				failureMessage = fmt.Sprintf("failed to fetch the status : %s", err.Error())
			} else if !ver.Verified {
				failureMessage = ver.Message
			}

			if failureMessage != "" {
				return nil, fmt.Errorf(failureMessage)
			}
		}
	}

	return vp, nil
}

func (o *Operation) sendHTTPRequest(req *http.Request, status int, token string) ([]byte, error) {
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("failed to read response body for status %d: %s", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func getCredentialChecks(profile *vcsstorage.VerifierProfile, opts *CredentialsVerificationOptions) []string {
	switch {
	case opts != nil && len(opts.Checks) != 0:
		return opts.Checks
	case len(profile.CredentialChecks) != 0:
		return profile.CredentialChecks
	}

	return []string{proofCheck}
}

func getPresentationChecks(profile *vcsstorage.VerifierProfile, opts *VerifyPresentationOptions) []string {
	switch {
	case opts != nil && len(opts.Checks) != 0:
		return opts.Checks
	case len(profile.PresentationChecks) != 0:
		return profile.PresentationChecks
	}

	return []string{proofCheck}
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

func validateProfileRequest(pr *vcsstorage.VerifierProfile) error {
	switch {
	case pr.ID == "":
		return errors.New("missing profile id")
	case pr.Name == "":
		return errors.New("missing profile name")
	case len(pr.CredentialChecks) != 0:
		for _, val := range pr.CredentialChecks {
			switch val {
			case proofCheck, statusCheck:
			default:
				return fmt.Errorf("invalid credential check option - %s", val)
			}
		}
	case len(pr.PresentationChecks) != 0:
		for _, val := range pr.PresentationChecks {
			switch val {
			case proofCheck:
			default:
				return fmt.Errorf("invalid presentation check option - %s", val)
			}
		}
	}

	return nil
}
