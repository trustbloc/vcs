/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
)

func (s *Service) RunOIDC4CIPreAuth(config *OIDC4VCIConfig, hooks *Hooks) (*verifiable.Credential, error) {
	log.Println("Starting OIDC4VCI pre-authorized code flow")

	startTime := time.Now()
	err := s.CreateWallet()
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}
	s.perfInfo.CreateWallet = time.Since(startTime)

	log.Printf("Initiate issuance URL:\n\n\t%s\n\n", config.CredentialOfferURI)

	parser := &credentialoffer.Parser{
		HTTPClient:  s.httpClient,
		VDRRegistry: s.ariesServices.vdrRegistry,
	}

	credentialOfferResponse, err := parser.Parse(config.CredentialOfferURI)
	if err != nil {
		return nil, fmt.Errorf("parse credential offer uri: %w", err)
	}

	s.print("Getting issuer OIDC config")
	startTime = time.Now()
	oidcIssuerCredentialConfig, err := s.GetWellKnownOpenIDConfiguration(credentialOfferResponse.CredentialIssuer)
	s.perfInfo.VcsCIFlowDuration += time.Since(startTime) // oidc config
	s.perfInfo.GetIssuerCredentialsOIDCConfig = time.Since(startTime)

	if err != nil {
		return nil, fmt.Errorf("get issuer OIDC issuer config: %w", err)
	}

	tokenValues := url.Values{
		"grant_type":          []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": []string{credentialOfferResponse.Grants.PreAuthorizationGrant.PreAuthorizedCode},
		"client_id":           []string{config.ClientID},
	}

	if credentialOfferResponse.Grants.PreAuthorizationGrant.UserPinRequired {
		if len(config.Pin) == 0 {
			log.Println("Enter PIN:")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			config.Pin = scanner.Text()
		}

		tokenValues.Add("user_pin", config.Pin)
	}

	s.print("Getting access token")
	startTime = time.Now()
	tokenResp, tokenErr := s.httpClient.PostForm(oidcIssuerCredentialConfig.TokenEndpoint, tokenValues)
	s.perfInfo.GetAccessToken = time.Since(startTime)
	s.perfInfo.VcsCIFlowDuration += time.Since(startTime)
	if tokenErr != nil {
		return nil, tokenErr
	}

	if tokenResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(tokenResp.Body)
		return nil, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, tokenResp.StatusCode, string(b))
	}

	var token oidc4ci.AccessTokenResponse
	if err = json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		return nil, err
	}
	_ = tokenResp.Body.Close()

	s.oauthClient = &oauth2.Config{
		ClientID: "oidc4vc_client",
		Endpoint: oauth2.Endpoint{
			TokenURL: oidcIssuerCredentialConfig.TokenEndpoint,
		},
	} // todo dynamic client registration
	s.token = lo.ToPtr(oauth2.Token{AccessToken: token.AccessToken}).WithExtra(map[string]interface{}{
		"c_nonce": *token.CNonce,
	})

	var beforeCredentialsRequestHooks []CredentialRequestOpt

	if hooks != nil {
		beforeCredentialsRequestHooks = hooks.BeforeCredentialRequest
	}

	s.print("Getting credential")
	startTime = time.Now()
	vc, vcsDuration, err := s.getCredential(
		oidcIssuerCredentialConfig.CredentialEndpoint,
		config.CredentialType,
		config.CredentialFormat,
		credentialOfferResponse.CredentialIssuer,
		beforeCredentialsRequestHooks...,
	)
	if err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}
	s.perfInfo.VcsCIFlowDuration += vcsDuration
	s.perfInfo.GetCredential = time.Since(startTime)

	b, err := json.Marshal(vc)
	if err != nil {
		return nil, fmt.Errorf("marshal vc: %w", err)
	}

	s.print("Adding credential to wallet")

	if err = s.wallet.Add(b); err != nil {
		return nil, fmt.Errorf("add credential to wallet: %w", err)
	}

	vcParsed, err := verifiable.ParseCredential(b,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(
			s.ariesServices.JSONLDDocumentLoader()))
	if err != nil {
		return nil, fmt.Errorf("parse vc: %w", err)
	}

	log.Printf("Credential with ID [%s] and type [%v] added successfully",
		vcParsed.Contents().ID, config.CredentialType)

	if !s.keepWalletOpen {
		s.wallet.Close()
	}

	return vcParsed, nil
}
