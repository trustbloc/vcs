/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/trustbloc/vc-go/verifiable"

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
)

func (e *Steps) initiateInteraction(profileVersionedID, organizationName string) error {
	return e.initiateInteractionHelper(profileVersionedID, organizationName, nil)
}

func (e *Steps) initiateInteractionHelper(profileVersionedID, organizationName string, body io.Reader) error {
	e.vpFlowExecutor = e.walletRunner.NewVPFlowExecutor(false)

	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	chunks := strings.Split(profileVersionedID, "/")
	if len(chunks) != 2 {
		return errors.New("initiateInteraction - invalid profileVersionedID field")
	}

	endpointURL := fmt.Sprintf(initiateOidcInteractionURLFormat, chunks[0], chunks[1])

	initiateInteractionResult, err := e.vpFlowExecutor.InitiateInteraction(endpointURL, token, body)
	if err != nil {
		return err
	}

	e.initiateOIDC4VPResponse = initiateInteractionResult
	e.verifierProfileVersionedID = profileVersionedID

	return nil
}

func (e *Steps) verifyAuthorizationRequestAndDecodeClaims() error {
	if len(e.initiateOIDC4VPResponse.AuthorizationRequest) == 0 {
		return fmt.Errorf("authorizationRequest is empty")
	}

	if len(e.initiateOIDC4VPResponse.TxId) == 0 {
		return fmt.Errorf("transactionID is empty")
	}

	return e.fetchRequestObjectAndDecodeClaims()
}

func (e *Steps) fetchRequestObjectAndDecodeClaims() error {
	rawRequestObject, _, err := e.vpFlowExecutor.FetchRequestObject(e.initiateOIDC4VPResponse.AuthorizationRequest)
	if err != nil {
		return err
	}

	_, err = e.waitForEvent("verifier.oidc-interaction-qr-scanned.v1")
	if err != nil {
		return err
	}

	return e.vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
}

func (e *Steps) queryCredentialFromWalletMultiVP() error {
	return e.vpFlowExecutor.QueryCredentialFromWalletMultiVP()
}

func (e *Steps) sendAuthorizedResponse() error {
	body, err := e.vpFlowExecutor.CreateAuthorizedResponse()
	if err != nil {
		return err
	}

	_, err = e.vpFlowExecutor.SendAuthorizedResponse(context.TODO(), body)
	return err
}

func (e *Steps) retrieveInteractionsClaim(organizationName string) error {
	txID, err := e.waitForEvent("verifier.oidc-interaction-succeeded.v1")
	if err != nil {
		return err
	}

	token := e.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	endpointURL := fmt.Sprintf(retrieveInteractionsClaimURLFormat, txID)

	claims, err := e.vpFlowExecutor.RetrieveInteractionsClaim(endpointURL, token)
	if err != nil {
		return fmt.Errorf("e.vpFlowExecutor.RetrieveInteractionsClaim: %w", err)
	}

	return e.validateRetrievedInteractionsClaim(claims)
}

func (e *Steps) validateRetrievedInteractionsClaim(claimsBytes []byte) error {
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return err
	}

	verifierProfile := e.bddContext.VerifierProfiles[e.verifierProfileVersionedID]

	// Check amount.
	if len(claims) != len(verifierProfile.PresentationDefinitions[0].InputDescriptors) {
		return fmt.Errorf("unexpected retrieved credentials amount. Expected %d, got %d",
			len(verifierProfile.PresentationDefinitions[0].InputDescriptors),
			len(claims),
		)
	}

	dl, err := bddutil.DocumentLoader()
	if err != nil {
		return err
	}

	// Check whether credentials are known.
	issuedVCID := make(map[string]struct{}, len(e.bddContext.CreatedCredentialsSet))

	for _, issuedVCBytes := range e.bddContext.CreatedCredentialsSet {
		var issuedVC *verifiable.Credential

		issuedVC, err = verifiable.ParseCredential(
			issuedVCBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(dl))
		if err != nil {
			return err
		}

		issuedVCID[issuedVC.ID] = struct{}{}
	}

	for retrievedVCID := range claims {
		_, exist := issuedVCID[retrievedVCID]
		if !exist {
			return fmt.Errorf("unexpected credential ID %s", retrievedVCID)
		}
	}

	return nil
}

func (e *Steps) waitForEvent(eventType string) (string, error) {
	incoming := &spi.Event{}

	for i := 0; i < pullTopicsAttemptsBeforeFail; {
		resp, err := bddutil.HTTPSDo(http.MethodGet, oidc4vpWebhookURL, "application/json", "", //nolint: bodyclose
			nil, e.tlsConfig)
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
