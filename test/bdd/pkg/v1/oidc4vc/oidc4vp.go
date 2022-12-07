/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

const (
	// retry options to pull topics from webhook
	// pullTopicsWaitInMilliSec is time in milliseconds to wait before retry.
	pullTopicsWaitInMilliSec = 200
	// pullTopicsAttemptsBeforeFail total number of retries where
	// total time shouldn't exceed 5 seconds.
	pullTopicsAttemptsBeforeFail = 5000 / pullTopicsWaitInMilliSec

	oidc4vpWebhookURL = "http://localhost:8180/checktopics"

	credentialServiceURL               = "https://localhost:4455"
	verifierProfileURL                 = credentialServiceURL + "/verifier/profiles"
	verifierProfileURLFormat           = verifierProfileURL + "/%s"
	InitiateOidcInteractionURLFormat   = verifierProfileURLFormat + "/interactions/initiate-oidc"
	RetrieveInteractionsClaimURLFormat = credentialServiceURL + "/verifier/interactions/%s/claim"
)

func (s *Steps) initiateInteraction(profileName, organizationName string) error {
	s.vpFlowExecutor = s.walletRunner.NewVPFlowExecutor(false)

	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	endpointURL := fmt.Sprintf(InitiateOidcInteractionURLFormat, profileName)
	initiateInteractionResult, err := s.vpFlowExecutor.InitiateInteraction(endpointURL, token)
	if err != nil {
		return err
	}

	s.initiateOIDC4VPResponse = initiateInteractionResult

	return nil
}

func (s *Steps) verifyAuthorizationRequest() error {
	if len(s.initiateOIDC4VPResponse.AuthorizationRequest) == 0 {
		return fmt.Errorf("authorizationRequest is empty")
	}

	if len(s.initiateOIDC4VPResponse.TxId) == 0 {
		return fmt.Errorf("transactionID is empty")
	}

	return nil
}

func (s *Steps) fetchRequestObjectAndDecodeClaims() error {
	rawRequestObject, err := s.vpFlowExecutor.FetchRequestObject(s.initiateOIDC4VPResponse.AuthorizationRequest)
	if err != nil {
		return err
	}

	_, err = s.waitForEvent("oidc_interaction_qr_scanned")
	if err != nil {
		return err
	}

	return s.vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
}

func (s *Steps) queryCredentialFromWallet() error {
	return s.vpFlowExecutor.QueryCredentialFromWallet()
}

func (s *Steps) checkRequestPresentation() error {
	if s.vpFlowExecutor.RequestPresentation() == nil {
		return fmt.Errorf("requestPresentation is empty")
	}

	return nil
}

func (s *Steps) sendAuthorizedResponse() error {
	body, err := s.vpFlowExecutor.CreateAuthorizedResponse()
	if err != nil {
		return err
	}

	return s.vpFlowExecutor.SendAuthorizedResponse(body)
}

func (s *Steps) retrieveInteractionsClaim(organizationName string) error {
	txID, err := s.waitForEvent("oidc_interaction_succeeded")
	if err != nil {
		return err
	}

	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	endpointURL := fmt.Sprintf(RetrieveInteractionsClaimURLFormat, txID)

	return s.vpFlowExecutor.RetrieveInteractionsClaim(endpointURL, token)
}

func (s *Steps) waitForEvent(eventType string) (string, error) {
	incoming := &spi.Event{}

	for i := 0; i < pullTopicsAttemptsBeforeFail; {

		resp, err := bddutil.HTTPSDo(http.MethodGet, oidc4vpWebhookURL, "application/json", "", //nolint: bodyclose
			nil, s.tlsConfig)
		if err != nil {
			return "", err
		}
		defer bddutil.CloseResponseBody(resp.Body)

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		if resp.StatusCode != http.StatusOK {
			return "", bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
		}

		err = json.Unmarshal(respBytes, incoming)
		if err != nil {
			return "", err
		}

		if incoming.Type == spi.EventType(eventType) {
			return incoming.TransactionID, nil
		}

		i++
		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}
	return "", errors.New("webhook waiting timeout exited")
}
