/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"bytes"
	"fmt"
	"time"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
)

type stressRequest struct {
	wallerRunner            *walletrunner.Service
	vpFlowExecutor          *walletrunner.VPFlowExecutor
	initiateOIDC4VPResponse *walletrunner.InitiateOIDC4VPResponse

	authToken                    string
	profileID                    string
	profileVersion               string
	initiateOIDC4VPData          []byte
	initiateInteractionURLFormat string
	retrieveClaimURLFormat       string
}

type stressRequestPerfInfo struct {
	initiateHTTPTime                  int64
	checkAuthorizedResponseHTTPTime   int64
	retrieveInteractionsClaimHTTPTime int64
}

func (r *stressRequest) Invoke() (string, interface{}, error) {
	perfInfo := stressRequestPerfInfo{}

	println("initiateInteraction started")

	startTime := time.Now()
	err := r.initiateInteraction()
	if err != nil {
		return "", nil, fmt.Errorf("initiate interaction %w", err)
	}

	perfInfo.initiateHTTPTime = time.Since(startTime).Milliseconds()

	println("fetchRequestObject started")

	rawRequestObject, err := r.fetchRequestObject()
	if err != nil {
		return "", nil, fmt.Errorf("featch request object %w", err)
	}

	err = r.verifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
	if err != nil {
		return "", nil, fmt.Errorf("verify authorization request %w", err)
	}

	err = r.queryCredentialFromWallet()
	if err != nil {
		return "", nil, fmt.Errorf("query credential from wallet %w", err)
	}

	authorizedResponse, err := r.createAuthorizedResponse()
	if err != nil {
		return "", nil, err
	}

	startTime = time.Now()

	err = r.sendAuthorizedResponse(authorizedResponse)
	if err != nil {
		return "", nil, err
	}

	perfInfo.checkAuthorizedResponseHTTPTime = time.Since(startTime).Milliseconds()

	startTime = time.Now()

	err = r.retrieveInteractionsClaim()
	if err != nil {
		return "", nil, err
	}

	perfInfo.retrieveInteractionsClaimHTTPTime = time.Since(startTime).Milliseconds()

	return "", perfInfo, nil
}

func (r *stressRequest) initiateInteraction() error {
	endpointURL := fmt.Sprintf(r.initiateInteractionURLFormat, r.profileID, r.profileVersion)

	initiateInteractionResult, err := r.vpFlowExecutor.InitiateInteraction(endpointURL, r.authToken, bytes.NewReader(r.initiateOIDC4VPData))
	if err != nil {
		return err
	}

	r.initiateOIDC4VPResponse = initiateInteractionResult

	return nil
}

func (r *stressRequest) fetchRequestObject() (string, error) {
	rawRequestObject, _, err := r.vpFlowExecutor.FetchRequestObject(r.initiateOIDC4VPResponse.AuthorizationRequest)
	if err != nil {
		return "", err
	}

	return rawRequestObject, nil
}

func (r *stressRequest) verifyAuthorizationRequestAndDecodeClaims(rawRequestObject string) error {
	return r.vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
}

func (r *stressRequest) queryCredentialFromWallet() error {
	return r.vpFlowExecutor.QueryCredentialFromWalletSingleVP()
}

func (r *stressRequest) createAuthorizedResponse() (string, error) {
	return r.vpFlowExecutor.CreateAuthorizedResponse()
}

func (r *stressRequest) sendAuthorizedResponse(responseBody string) error {
	_, err := r.vpFlowExecutor.SendAuthorizedResponse(responseBody)
	return err
}

func (r *stressRequest) retrieveInteractionsClaim() error {
	endpointURL := fmt.Sprintf(r.retrieveClaimURLFormat, r.initiateOIDC4VPResponse.TxId)

	return r.vpFlowExecutor.RetrieveInteractionsClaim(endpointURL, r.authToken)
}

type initiateOIDC4VPData struct {
	PresentationDefinitionId      string                         `json:"presentationDefinitionId,omitempty"`
	PresentationDefinitionFilters *presentationDefinitionFilters `json:"presentationDefinitionFilters,omitempty"`
}

type presentationDefinitionFilters struct {
	Fields *[]string `json:"fields,omitempty"`
}
