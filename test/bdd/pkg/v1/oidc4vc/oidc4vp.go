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

	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vp"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
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

	credentialServiceURL             = "https://api-gateway.trustbloc.local:5566"
	verifierProfileURL               = credentialServiceURL + "/verifier/profiles"
	verifierProfileURLFormat         = verifierProfileURL + "/%s/%s"
	initiateOidcInteractionURLFormat = verifierProfileURLFormat + "/interactions/initiate-oidc"
	interactionsClaimURLFormat       = credentialServiceURL + "/verifier/interactions/%s/claim"
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

func (s *Steps) initiateOIDC4VPInteraction(req *initiateOIDC4VPRequest) (*initiateOIDC4VPResponse, error) {
	endpointURL := fmt.Sprintf(initiateOidcInteractionURLFormat, s.verifierProfile.ID, s.verifierProfile.Version)
	token := s.bddContext.Args[getOrgAuthTokenKey(s.verifierProfile.ID+"/"+s.verifierProfile.Version)]

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal initiate oidc4vp req: %w", err)
	}

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, bytes.NewReader(reqBody),
		s.bddContext.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("https do: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, b)
	}

	var r *initiateOIDC4VPResponse

	if err = json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("unmarshal initiate oidc4vp resp: %w", err)
	}

	return r, nil
}

func (s *Steps) retrieveInteractionsClaim(_ string) error {
	if err := s.waitForOIDC4VPEvent(string(spi.VerifierOIDCInteractionSucceeded)); err != nil {
		return err
	}

	claims, err := s.retrieveCredentialClaims(s.vpClaimsTransactionID)
	if err != nil {
		return err
	}

	return s.validateRetrievedCredentialClaims(claims)
}

func (s *Steps) retrieveInteractionsClaimWithCustomScopes(_, customScopes string) error {
	if err := s.waitForOIDC4VPEvent(string(spi.VerifierOIDCInteractionSucceeded)); err != nil {
		return err
	}

	claims, err := s.retrieveCredentialClaims(s.vpClaimsTransactionID)
	if err != nil {
		return err
	}

	scopeClaims, ok := claims["_scope"]
	if !ok {
		return errors.New("_scope claim expected")
	}

	for _, scope := range strings.Split(customScopes, ",") {
		customScopeClaims, ok := scopeClaims.CustomClaims[scope]
		if !ok || len(customScopeClaims) == 0 {
			return fmt.Errorf("no additional claims supplied for custom scope %s", scope)
		}
	}

	delete(claims, "_scope")

	return s.validateRetrievedCredentialClaims(claims)
}

func (s *Steps) retrieveExpiredOrDeletedInteractionsClaim(profile string) error {
	if _, err := s.retrieveCredentialClaims(s.vpClaimsTransactionID); err == nil {
		return fmt.Errorf("error expected, but got nil")
	}

	return nil
}

func (s *Steps) retrieveCredentialClaims(txID string) (retrievedCredentialClaims, error) {
	endpointURL := fmt.Sprintf(interactionsClaimURLFormat, txID)
	token := s.bddContext.Args[getOrgAuthTokenKey(s.verifierProfile.ID+"/"+s.verifierProfile.Version)]

	resp, err := bddutil.HTTPSDo(http.MethodGet, endpointURL, "application/json", token, nil, s.bddContext.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("https do: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, b)
	}

	var claims retrievedCredentialClaims

	if err = json.Unmarshal(b, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal credential claims: %w", err)
	}

	return claims, nil
}

func (s *Steps) validateRetrievedCredentialClaims(claims retrievedCredentialClaims) error {
	var pd *presexch.PresentationDefinition
	for _, verifierPD := range s.verifierProfile.PresentationDefinitions {
		if verifierPD.ID == s.presentationDefinitionID {
			pd = verifierPD
			break
		}
	}

	// Check whether credentials are known.
	credentialMap, err := s.wallet.GetAll()
	if err != nil {
		return fmt.Errorf("wallet.GetAll(): %w", err)
	}

	expectedCredentials := s.expectedCredentialsAmountForVP
	if expectedCredentials == 0 {
		expectedCredentials = len(pd.InputDescriptors)
	}

	if len(claims) != expectedCredentials {
		return fmt.Errorf("unexpected retrieved credentials amount. Expected %d, got %d",
			expectedCredentials,
			len(claims),
		)
	}

	issuedVCID := make(map[string]struct{}, len(credentialMap))
	for _, vcBytes := range credentialMap {
		var vcParsed *verifiable.Credential
		vcParsed, err = verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader))
		if err != nil {
			return fmt.Errorf("parse credential from wallet: %w", err)
		}

		issuedVCID[vcParsed.Contents().ID] = struct{}{}
	}

	for retrievedVCID, val := range claims {
		_, exist := issuedVCID[retrievedVCID]

		if !exist {
			return fmt.Errorf("unexpected credential ID %s", retrievedVCID)
		}

		var attachments []string
		for _, attachment := range val.Attachments {
			attachments = append(attachments, attachment.DataURI)
		}

		if len(s.expectedAttachment) > 0 {
			if len(attachments) != len(s.expectedAttachment) {
				return fmt.Errorf("unexpected attachment amount. Expected %d, got %d",
					len(s.expectedAttachment),
					len(attachments),
				)
			}

			for _, expectedAttachment := range s.expectedAttachment {
				if !lo.Contains(attachments, expectedAttachment) {
					return fmt.Errorf("attachment %s not found", expectedAttachment)
				}
			}
		}

	}

	return nil
}

func (s *Steps) runOIDC4VPFlow(profileVersionedID, pdID, fields string) error {
	return s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields, nil, false)
}

func (s *Steps) runOIDC4VPFlowWithCustomScopes(profileVersionedID, pdID, fields, customScopes string) error {
	return s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields, strings.Split(customScopes, ","), false)
}

func (s *Steps) runOIDC4VPFlowWithMultiVPs(profileVersionedID, pdID, fields string) error {
	return s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields, nil, true)
}

func (s *Steps) runOIDC4VPFlowWithError(profileVersionedID, pdID, fields, errorContains string) error {
	err := s.runOIDC4VPFlowWithOpts(profileVersionedID, pdID, fields, nil, false)
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error on runOIDC4VPFlowWithError: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VPFlowWithOpts(
	profileVersionedID, pdID, fields string,
	scopes []string,
	useMultiVPs bool,
) error {
	s.verifierProfile = s.bddContext.VerifierProfiles[profileVersionedID]
	s.presentationDefinitionID = pdID

	fieldsArr := strings.Split(fields, ",")

	req := &initiateOIDC4VPRequest{
		PresentationDefinitionId: pdID,
		PresentationDefinitionFilters: &presentationDefinitionFilters{
			Fields: &fieldsArr,
		},
	}

	if len(scopes) > 0 {
		req.Scopes = scopes
	}

	initiateInteractionResult, err := s.initiateOIDC4VPInteraction(req)
	if err != nil {
		return fmt.Errorf("init oidc4vp interaction: %w", err)
	}

	requestURI := strings.SplitN(initiateInteractionResult.AuthorizationRequest, "?request_uri=", 2)
	if len(requestURI) != 2 {
		return fmt.Errorf("invalid AuthorizationRequest format: %s", initiateInteractionResult.AuthorizationRequest)
	}

	opts := []oidc4vp.Opt{
		oidc4vp.WithRequestURI(requestURI[1]),
		oidc4vp.WithDomainMatchingDisabled(),
		oidc4vp.WithSchemaValidationDisabled(),
	}

	if len(s.vpAttachments) > 0 {
		opts = append(opts, oidc4vp.WithAttachments(s.vpAttachments))
	}

	if useMultiVPs {
		opts = append(opts, oidc4vp.WithMultiVPs())
	}

	flow, err := oidc4vp.NewFlow(s.oidc4vpProvider, opts...)
	if err != nil {
		return fmt.Errorf("init flow: %w", err)
	}

	if err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run vp flow: %w", err)
	}

	return nil
}

func (s *Steps) setHardcodedVPTokenFormat(vpTokenFormat string) error {
	//s.oidc4vpHooks = &walletrunner.OIDC4VPHooks{
	//	CreateAuthorizedResponse: []walletrunner.RPConfigOverride{
	//		walletrunner.WithSupportedVPFormat(vcs.Format(vpTokenFormat)),
	//	},
	//}

	return nil
}

func (s *Steps) waitForOIDC4VPEvent(eventType string) error {
	event, err := s.waitForEvent(spi.EventType(eventType))
	if err != nil {
		return err
	}

	s.vpClaimsTransactionID = event.TransactionID

	switch spi.EventType(eventType) {
	case spi.VerifierOIDCInteractionSucceeded, spi.VerifierOIDCInteractionNoConsent, spi.VerifierOIDCInteractionNoMatchFound:
		if err = checkEventInteractionDetailsClaim(event); err != nil {
			return err
		}
	}

	return nil
}

func (s *Steps) waitForEvent(eventType spi.EventType) (*spi.Event, error) {
	incoming := &spi.Event{}

	for i := 0; i < pullTopicsAttemptsBeforeFail; {
		resp, err := bddutil.HTTPSDo(http.MethodGet, oidc4vpWebhookURL, "application/json", "", //nolint: bodyclose
			nil, s.tlsConfig)
		if err != nil {
			return nil, err
		}

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		bddutil.CloseResponseBody(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
		}

		err = json.Unmarshal(respBytes, incoming)
		if err != nil {
			return nil, err
		}

		if incoming.Type == eventType {
			return incoming, nil
		}

		i++
		time.Sleep(pullTopicsWaitInMilliSec * time.Millisecond)
	}

	return nil, errors.New("webhook waiting timeout exited")
}

type oidc4vpProvider struct {
	storageProvider    storageapi.Provider
	httpClient         *http.Client
	documentLoader     ld.DocumentLoader
	vdrRegistry        vdrapi.Registry
	cryptoSuite        api.Suite
	attestationService *attestation.Service
	trustRegistry      *trustregistry.Client
	wallet             *wallet.Wallet
}

func (p *oidc4vpProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vpProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vpProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vpProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vpProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *oidc4vpProvider) AttestationService() oidc4vp.AttestationService {
	return p.attestationService
}

func (p *oidc4vpProvider) TrustRegistry() oidc4vp.TrustRegistry {
	return p.trustRegistry
}

func (p *oidc4vpProvider) Wallet() *wallet.Wallet {
	return p.wallet
}
