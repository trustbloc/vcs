/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	commhttp "github.com/trustbloc/edge-service/pkg/restapi/internal/common/http"
)

const (
	// verifier endpoints
	verifierBasePath                  = "/verifier"
	credentialsVerificationEndpoint   = verifierBasePath + "/credentials"
	presentationsVerificationEndpoint = verifierBasePath + "/presentations"

	invalidRequestErrMsg = "Invalid request"

	successMsg = "success"

	// credential verification checks
	proofCheck  = "proof"
	statusCheck = "status"

	// proof data keys
	challenge          = "challenge"
	domain             = "domain"
	proofPurpose       = "proofPurpose"
	verificationMethod = "verificationMethod"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// New returns CreateCredential instance
func New(config *Config) (*Operation, error) {
	svc := &Operation{
		vdri:       config.VDRI,
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
	}

	return svc, nil
}

// Config defines configuration for verifier operations
type Config struct {
	VDRI      vdriapi.Registry
	TLSConfig *tls.Config
}

// Operation defines handlers for Edge service
type Operation struct {
	vdri       vdriapi.Registry
	httpClient httpClient
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() ([]Handler, error) {
	return []Handler{
		support.NewHTTPHandler(credentialsVerificationEndpoint, http.MethodPost, o.verifyCredentialHandler),
		support.NewHTTPHandler(presentationsVerificationEndpoint, http.MethodPost,
			o.verifyPresentationHandler),
	}, nil
}

// nolint dupl
// VerifyCredential swagger:route POST /verifier/credentials verifier verifyCredentialReq
//
// Verifies a credential.
//
// Responses:
//    default: genericError
//        200: verifyCredentialSuccessResp
//        400: verifyCredentialFailureResp
func (o *Operation) verifyCredentialHandler(rw http.ResponseWriter, req *http.Request) {
	// get the request
	verificationReq := CredentialsVerificationRequest{}

	err := json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	vc, err := verifiable.NewUnverifiedCredential(verificationReq.Credential)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	checks := []string{proofCheck}

	// if req contains checks, then override the default checks
	if verificationReq.Opts != nil && len(verificationReq.Opts.Checks) != 0 {
		checks = verificationReq.Opts.Checks
	}

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
			if vc.Status != nil && vc.Status.ID != "" {
				ver, err := o.checkVCStatus(vc.Status.ID, vc.ID)

				if err != nil {
					failureMessage = fmt.Sprintf("failed to fetch the status : %s", err.Error())
				} else if !ver.Verified {
					failureMessage = ver.Message
				}
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
		rw.WriteHeader(http.StatusOK)
		commhttp.WriteResponse(rw, &CredentialsVerificationSuccessResponse{
			Checks: checks,
		})
	} else {
		rw.WriteHeader(http.StatusBadRequest)
		commhttp.WriteResponse(rw, &CredentialsVerificationFailResponse{
			Checks: result,
		})
	}
}

// VerifyPresentation swagger:route POST /verifier/presentations verifier verifyPresentationReq
//
// Verifies a presentation.
//
// Responses:
//    default: genericError
//        200: verifyPresentationSuccessResp
//        400: verifyPresentationFailureResp
func (o *Operation) verifyPresentationHandler(rw http.ResponseWriter, req *http.Request) {
	// get the request
	verificationReq := VerifyPresentationRequest{}

	err := json.NewDecoder(req.Body).Decode(&verificationReq)
	if err != nil {
		commhttp.WriteErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	checks := []string{proofCheck}

	// if req contains checks, then override the default checks
	if verificationReq.Opts != nil && len(verificationReq.Opts.Checks) != 0 {
		checks = verificationReq.Opts.Checks
	}

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
		default:
			result = append(result, VerifyPresentationCheckResult{
				Check: val,
				Error: "check not supported",
			})
		}
	}

	if len(result) == 0 {
		rw.WriteHeader(http.StatusOK)
		commhttp.WriteResponse(rw, &VerifyPresentationSuccessResponse{
			Checks: checks,
		})
	} else {
		rw.WriteHeader(http.StatusBadRequest)
		commhttp.WriteResponse(rw, &VerifyPresentationFailureResponse{
			Checks: result,
		})
	}
}

func (o *Operation) validateCredentialProof(vcByte []byte, opts *CredentialsVerificationOptions,
	vcInVPValidation bool) error {
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

	// TODO https://github.com/trustbloc/edge-service/issues/412 figure out the process when vc has more than one proof
	proof := vc.Proofs[0]

	if !vcInVPValidation {
		// validate challenge
		if err := validateProofData(proof, challenge, opts.Challenge); err != nil {
			return err
		}

		// validate domain
		if err := validateProofData(proof, domain, opts.Domain); err != nil {
			return err
		}
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, o.vdri); err != nil {
		return fmt.Errorf("verifiable credential proof purpose validation error : %w", err)
	}

	return nil
}

func (o *Operation) validatePresentationProof(vpByte []byte, opts *VerifyPresentationOptions) error {
	vp, err := o.parseAndVerifyVP(vpByte)

	if err != nil {
		return fmt.Errorf("verifiable presentation proof validation error : %w", err)
	}

	// validate proof challenge and domain
	if opts == nil {
		opts = &VerifyPresentationOptions{}
	}

	var proof verifiable.Proof

	// TODO https://github.com/trustbloc/edge-service/issues/412 figure out the process when vc has more than one proof
	if len(vp.Proofs) != 0 {
		proof = vp.Proofs[0]
	}

	// validate challenge
	if err := validateProofData(proof, challenge, opts.Challenge); err != nil {
		return err
	}

	// validate domain
	if err := validateProofData(proof, domain, opts.Domain); err != nil {
		return err
	}

	// validate proof purpose
	if err := validateProofPurpose(proof, o.vdri); err != nil {
		return fmt.Errorf("verifiable presentation proof purpose validation error : %w", err)
	}

	return nil
}

func (o *Operation) checkVCStatus(vclID, vcID string) (*VerifyCredentialResponse, error) {
	vcResp := &VerifyCredentialResponse{
		Verified: false}

	req, err := http.NewRequest(http.MethodGet, vclID, nil)
	if err != nil {
		return nil, err
	}

	resp, err := o.sendHTTPRequest(req, http.StatusOK)
	if err != nil {
		return nil, err
	}

	var csl cslstatus.CSL
	if err := json.Unmarshal(resp, &csl); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp to csl: %w", err)
	}

	for _, vcStatus := range csl.VC {
		if !strings.Contains(vcStatus, vcID) {
			continue
		}

		statusVc, err := o.parseAndVerifyVC([]byte(vcStatus))
		if err != nil {
			return nil, fmt.Errorf("failed to parse and verify status vc: %s", err.Error())
		}

		subjectBytes, err := json.Marshal(statusVc.Subject)
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("failed to marshal status vc subject: %s", err.Error()))
		}

		vcResp.Message = string(subjectBytes)

		return vcResp, nil
	}

	vcResp.Verified = true
	vcResp.Message = successMsg

	return vcResp, nil
}

func (o *Operation) parseAndVerifyVCStrictMode(vcBytes []byte) (*verifiable.Credential, error) {
	vc, _, err := verifiable.NewCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
		verifiable.WithStrictValidation(),
	)

	if err != nil {
		return nil, err
	}

	return vc, nil
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

func validateProofPurpose(proof verifiable.Proof, vdri vdriapi.Registry) error {
	purposeVal, ok := proof[proofPurpose]
	if !ok {
		return errors.New("proof doesn't have purpose")
	}

	purpose, ok := purposeVal.(string)
	if !ok {
		return errors.New("proof purpose is not a string")
	}

	verificationMethodVal, ok := proof[verificationMethod]
	if !ok {
		return errors.New("proof doesn't have verification method")
	}

	verificationMethod, ok := verificationMethodVal.(string)
	if !ok {
		return errors.New("proof verification method is not a string")
	}

	return crypto.ValidateProofPurpose(purpose, verificationMethod, vdri)
}

func (o *Operation) parseAndVerifyVP(vpBytes []byte) (*verifiable.Presentation, error) {
	vp, err := verifiable.NewPresentation(
		vpBytes,
		verifiable.WithPresPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
	)

	if err != nil {
		return nil, err
	}
	// vp is verified

	// verify if the credentials in vp are valid
	for _, cred := range vp.Credentials() {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}
		// verify if the credential in vp is valid
		err = o.validateCredentialProof(vcBytes, nil, true)
		if err != nil {
			return nil, err
		}
	}

	return vp, nil
}

func (o *Operation) sendHTTPRequest(req *http.Request, status int) ([]byte, error) {
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Warn("failed to close response body")
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warnf("failed to read response body for status %d: %s", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (o *Operation) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	vc, _, err := verifiable.NewCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewDIDKeyResolver(o.vdri).PublicKeyFetcher(),
		),
	)

	if err != nil {
		return nil, err
	}

	return vc, nil
}
