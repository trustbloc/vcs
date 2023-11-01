/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
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

func (s *Steps) authorizeVerifierProfileUser(profileVersionedID, username, password string) error {
	verifierProfile, ok := s.bddContext.VerifierProfiles[profileVersionedID]
	if !ok {
		return fmt.Errorf("verifier profile '%s' not found", profileVersionedID)
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL,
		username, password, []string{"org_admin"})
	if err != nil {
		return err
	}

	s.bddContext.Args[getOrgAuthTokenKey(verifierProfile.ID+"/"+verifierProfile.Version)] = accessToken

	s.verifierProfile = verifierProfile

	return nil
}

type initiateOIDCVPFlowOpt func(d *initiateOIDC4VPData)

func (s *Steps) runOIDC4VPFlow(profileVersionedID, pdID, fields string) error {
	return s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields)
}

func (s *Steps) runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields string, opts ...initiateOIDCVPFlowOpt) error {
	s.verifierProfile = s.bddContext.VerifierProfiles[profileVersionedID]
	s.presentationDefinitionID = pdID

	providerConf := s.walletRunner.GetConfig()
	providerConf.WalletUserId = providerConf.WalletParams.UserID
	providerConf.WalletPassPhrase = providerConf.WalletParams.Passphrase
	providerConf.WalletDidID = providerConf.WalletParams.DidID[0]
	providerConf.WalletDidKeyID = providerConf.WalletParams.DidKeyID[0]
	providerConf.SkipSchemaValidation = true

	fieldsArr := strings.Split(fields, ",")

	d := &initiateOIDC4VPData{
		PresentationDefinitionId: pdID,
		PresentationDefinitionFilters: &presentationDefinitionFilters{
			Fields: &fieldsArr,
		},
	}

	for _, f := range opts {
		f(d)
	}

	reqBody, err := json.Marshal(d)
	if err != nil {
		return err
	}

	chunks := strings.Split(profileVersionedID, "/")
	if len(chunks) != 2 {
		return errors.New("runOIDC4VPFlow - invalid profileVersionedID field")
	}

	endpointURL := fmt.Sprintf(InitiateOidcInteractionURLFormat, chunks[0], chunks[1])
	token := s.bddContext.Args[getOrgAuthTokenKey(s.verifierProfile.ID+"/"+s.verifierProfile.Version)]
	vpFlowExecutor := s.walletRunner.NewVPFlowExecutor(true)

	initiateInteractionResult, err := vpFlowExecutor.InitiateInteraction(endpointURL, token, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("OIDC4Vp fetch authorization request: %w", err)
	}

	err = s.walletRunner.RunOIDC4VPFlow(context.TODO(), initiateInteractionResult.AuthorizationRequest, s.oidc4vpHooks)
	if err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4VPFlow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VPFlowWithCustomScope(profileVersionedID, pdID, fields, customScope string) error {
	return s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields, func(d *initiateOIDC4VPData) {
		d.Scope = customScope
	})
}

func (s *Steps) runOIDC4VPFlowWithError(profileVersionedID, pdID, fields, errorContains string) error {
	err := s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields)
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error on runOIDC4VPFlowWithError: %w", err)
	}

	return nil
}

func (s *Steps) setHardcodedVPTokenFormat(vpTokenFormat string) error {
	s.oidc4vpHooks = &walletrunner.OIDC4VPHooks{
		CreateAuthorizedResponse: []walletrunner.RPConfigOverride{
			walletrunner.WithSupportedVPFormat(vcs.Format(vpTokenFormat)),
		},
	}

	return nil
}

func (s *Steps) waitForOIDCInteractionSucceededEvent(profile string) error {
	txID, err := s.waitForEvent("verifier.oidc-interaction-succeeded.v1")
	if err != nil {
		return err
	}

	s.vpClaimsTransactionID = txID

	return nil
}

func (s *Steps) retrieveInteractionsClaim(profile string) error {
	if err := s.waitForOIDCInteractionSucceededEvent(profile); err != nil {
		return err
	}

	token := s.bddContext.Args[getOrgAuthTokenKey(s.verifierProfile.ID+"/"+s.verifierProfile.Version)]
	endpointURL := fmt.Sprintf(RetrieveInteractionsClaimURLFormat, s.vpClaimsTransactionID)

	claims, err := s.walletRunner.NewVPFlowExecutor(true).RetrieveInteractionsClaim(endpointURL, token)
	if err != nil {
		return err
	}

	var credentialClaims map[string]retrievedCredentialsClaims
	if err = json.Unmarshal(claims, &credentialClaims); err != nil {
		return err
	}

	return s.validateRetrievedInteractionsClaim(credentialClaims)
}

func (s *Steps) retrieveInteractionsClaimWithCustomScope(profile, customScope string) error {
	if err := s.waitForOIDCInteractionSucceededEvent(profile); err != nil {
		return err
	}

	token := s.bddContext.Args[getOrgAuthTokenKey(s.verifierProfile.ID+"/"+s.verifierProfile.Version)]
	endpointURL := fmt.Sprintf(RetrieveInteractionsClaimURLFormat, s.vpClaimsTransactionID)

	claims, err := s.walletRunner.NewVPFlowExecutor(true).RetrieveInteractionsClaim(endpointURL, token)
	if err != nil {
		return err
	}

	var credentialClaims map[string]retrievedCredentialsClaims
	if err = json.Unmarshal(claims, &credentialClaims); err != nil {
		return err
	}

	customClaimsMetadata, ok := credentialClaims["_scope"]
	if !ok {
		return errors.New("_scope claim expected")
	}

	customScopeClaims, ok := customClaimsMetadata.CustomClaims[customScope]
	if !ok || len(customScopeClaims) == 0 {
		return fmt.Errorf("no additional claims supplied for custom scope %s", customScope)
	}

	delete(credentialClaims, "_scope")

	return s.validateRetrievedInteractionsClaim(credentialClaims)
}

func (s *Steps) validateRetrievedInteractionsClaim(credentialClaims map[string]retrievedCredentialsClaims) error {
	// Check amount.
	var pd *presexch.PresentationDefinition
	for _, verifierPD := range s.verifierProfile.PresentationDefinitions {
		if verifierPD.ID == s.presentationDefinitionID {
			pd = verifierPD
			break
		}
	}

	if len(credentialClaims) != len(pd.InputDescriptors) {
		return fmt.Errorf("unexpected retrieved credentials amount. Expected %d, got %d",
			len(pd.InputDescriptors),
			len(credentialClaims),
		)
	}

	// Check whether credentials are known.
	credentialMap, err := s.walletRunner.GetWallet().GetAll()
	if err != nil {
		return fmt.Errorf("wallet.GetAll(): %w", err)
	}

	issuedVCID := make(map[string]struct{}, len(credentialMap))
	for _, vcBytes := range credentialMap {
		var vcParsed *verifiable.Credential
		vcParsed, err = verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(s.dl))
		if err != nil {
			return fmt.Errorf("parse credential from wallet: %w", err)
		}

		issuedVCID[vcParsed.Contents().ID] = struct{}{}
	}

	for retrievedVCID := range credentialClaims {
		_, exist := issuedVCID[retrievedVCID]
		if !exist {
			return fmt.Errorf("unexpected credential ID %s", retrievedVCID)
		}
	}

	return nil
}

func (s *Steps) retrieveExpiredOrDeletedInteractionsClaim(profile string) error {
	token := s.bddContext.Args[getOrgAuthTokenKey(s.verifierProfile.ID+"/"+s.verifierProfile.Version)]

	endpointURL := fmt.Sprintf(RetrieveInteractionsClaimURLFormat, s.vpClaimsTransactionID)

	if _, err := s.walletRunner.NewVPFlowExecutor(true).RetrieveInteractionsClaim(endpointURL, token); err == nil {
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
	// Additional scope that defines custom claims requested from Holder to Verifier.
	Scope                         string                         `json:"scope,omitempty"`
	PresentationDefinitionId      string                         `json:"presentationDefinitionId,omitempty"`
	PresentationDefinitionFilters *presentationDefinitionFilters `json:"presentationDefinitionFilters,omitempty"`
}

type presentationDefinitionFilters struct {
	Fields *[]string `json:"fields,omitempty"`
}
