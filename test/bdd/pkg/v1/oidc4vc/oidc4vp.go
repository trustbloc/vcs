/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	credentialServiceURL               = "https://api-gateway.trustbloc.local:5566"
	verifierProfileURL                 = credentialServiceURL + "/verifier/profiles"
	verifierProfileURLFormat           = verifierProfileURL + "/%s/%s"
	InitiateOidcInteractionURLFormat   = verifierProfileURLFormat + "/interactions/initiate-oidc"
	RetrieveInteractionsClaimURLFormat = credentialServiceURL + "/verifier/interactions/%s/claim"
)

func (s *Steps) runOIDC4VPFlow(profileVersionedID, organizationName, pdID, fields string) error {
	providerConf := s.walletRunner.GetConfig()
	providerConf.WalletUserId = providerConf.WalletParams.UserID
	providerConf.WalletPassPhrase = providerConf.WalletParams.Passphrase
	providerConf.WalletDidID = providerConf.WalletParams.DidID[0]
	providerConf.WalletDidKeyID = providerConf.WalletParams.DidKeyID[0]
	providerConf.SkipSchemaValidation = true

	fieldsArr := strings.Split(fields, ",")

	reqBody, err := json.Marshal(&initiateOIDC4VPData{
		PresentationDefinitionId: pdID,
		PresentationDefinitionFilters: &presentationDefinitionFilters{
			Fields: &fieldsArr,
		},
	})
	if err != nil {
		return err
	}

	chunks := strings.Split(profileVersionedID, "/")
	if len(chunks) != 2 {
		return errors.New("runOIDC4VPFlow - invalid profileVersionedID field")
	}

	endpointURL := fmt.Sprintf(InitiateOidcInteractionURLFormat, chunks[0], chunks[1])
	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	vpFlowExecutor := s.walletRunner.NewVPFlowExecutor(true)

	initiateInteractionResult, err := vpFlowExecutor.InitiateInteraction(endpointURL, token, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("OIDC4Vp fetch authorization request: %w", err)
	}

	err = s.walletRunner.RunOIDC4VPFlow(initiateInteractionResult.AuthorizationRequest)
	if err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4VPFlow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VPFlowWithError(profileVersionedID, organizationName, pdID, fields, errorContains string) error {
	err := s.runOIDC4VPFlow(profileVersionedID, organizationName, pdID, fields)
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error on runOIDC4VPFlowWithError: %w", err)
	}

	return nil
}

func (s *Steps) waitForOIDCInteractionSucceededEvent(organizationName string) error {
	txID, err := s.waitForEvent("verifier.oidc-interaction-succeeded.v1")
	if err != nil {
		return err
	}

	s.vpClaimsTransactionID = txID

	return nil
}

func (s *Steps) retrieveInteractionsClaim(organizationName string) error {
	if err := s.waitForOIDCInteractionSucceededEvent(organizationName); err != nil {
		return err
	}

	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]
	endpointURL := fmt.Sprintf(RetrieveInteractionsClaimURLFormat, s.vpClaimsTransactionID)

	return s.walletRunner.NewVPFlowExecutor(true).RetrieveInteractionsClaim(endpointURL, token)
}

func (s *Steps) retrieveExpiredOrDeletedInteractionsClaim(organizationName string) error {
	token := s.bddContext.Args[getOrgAuthTokenKey(organizationName)]

	endpointURL := fmt.Sprintf(RetrieveInteractionsClaimURLFormat, s.vpClaimsTransactionID)

	if err := s.walletRunner.NewVPFlowExecutor(true).RetrieveInteractionsClaim(endpointURL, token); err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	return nil
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

type initiateOIDC4VPData struct {
	PresentationDefinitionId      string                         `json:"presentationDefinitionId,omitempty"`
	PresentationDefinitionFilters *presentationDefinitionFilters `json:"presentationDefinitionFilters,omitempty"`
}

type presentationDefinitionFilters struct {
	Fields *[]string `json:"fields,omitempty"`
}
