/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/credentialoffer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
)

func (s *Service) RunOIDC4CIPreAuth(config *OIDC4CIConfig) error {
	log.Println("Starting OIDC4VCI pre-authorized code flow")

	log.Printf("Initiate issuance URL:\n\n\t%s\n\n", config.InitiateIssuanceURL)
	offerResponse, err := credentialoffer.ParseInitiateIssuanceUrl(config.InitiateIssuanceURL, s.httpClient)
	if err != nil {
		return fmt.Errorf("parse initiate issuance url: %w", err)
	}

	s.print("Getting issuer OIDC config")
	startTime := time.Now()
	oidcConfig, err := s.getIssuerOIDCConfig(offerResponse.CredentialIssuer)
	s.perfInfo.VcsCIFlowDuration += time.Since(startTime) // oidc config

	if err != nil {
		return err
	}
	oidcIssuerCredentialConfig, err := s.getIssuerCredentialsOIDCConfig(offerResponse.CredentialIssuer)
	s.perfInfo.VcsCIFlowDuration += time.Since(startTime) // oidc config
	s.perfInfo.GetIssuerOIDCConfig = time.Since(startTime)

	if err != nil {
		return fmt.Errorf("get issuer oidc issuer config: %w", err)
	}

	tokenEndpoint := oidcConfig.TokenEndpoint
	credentialsEndpoint := oidcIssuerCredentialConfig.CredentialEndpoint

	tokenValues := url.Values{
		"grant_type":          []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": []string{offerResponse.Grants.PreAuthorizationGrant.PreAuthorizedCode},
	}

	if offerResponse.Grants.PreAuthorizationGrant.UserPinRequired {
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
	tokenResp, tokenErr := s.httpClient.PostForm(tokenEndpoint, tokenValues)
	s.perfInfo.GetAccessToken = time.Since(startTime)
	s.perfInfo.VcsCIFlowDuration += time.Since(startTime)
	if tokenErr != nil {
		return tokenErr
	}

	var token oidc4ci.AccessTokenResponse
	if err = json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		return err
	}
	_ = tokenResp.Body.Close()

	s.oauthClient = &oauth2.Config{ClientID: "oidc4vc_client"} // todo dynamic client registration
	s.token = lo.ToPtr(oauth2.Token{AccessToken: token.AccessToken}).WithExtra(map[string]interface{}{
		"c_nonce": *token.CNonce,
	})

	startTime = time.Now()
	err = s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}
	s.perfInfo.CreateWallet = time.Since(startTime)

	s.print("Getting credential")
	startTime = time.Now()
	vc, vcsDuration, err := s.getCredential(credentialsEndpoint, config.CredentialType, config.CredentialFormat)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}
	s.perfInfo.VcsCIFlowDuration += vcsDuration
	s.perfInfo.GetCredential = time.Since(startTime)

	b, err := json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	log.Printf(string(b))

	s.print("Adding credential to wallet")

	if err = s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, b); err != nil {
		return fmt.Errorf("add credential to wallet: %w", err)
	}

	vcParsed, err := verifiable.ParseCredential(b,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(
			s.ariesServices.JSONLDDocumentLoader()))
	if err != nil {
		return fmt.Errorf("parse vc: %w", err)
	}

	log.Printf("Credential with ID [%s] and type [%v] added successfully", vcParsed.ID, config.CredentialType)

	if !s.keepWalletOpen {
		s.wallet.Close()
	}

	return nil
}
