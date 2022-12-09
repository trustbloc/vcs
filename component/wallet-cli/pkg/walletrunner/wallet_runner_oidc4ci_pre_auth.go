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
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
)

func (s *Service) RunOIDC4CIPreAuth(config *OIDC4CIConfig) error {
	log.Println("Starting OIDC4VCI pre-authorized code flow")

	log.Printf("Initiate issuance URL:\n\n\t%s\n\n", config.InitiateIssuanceURL)
	parsedUrl, err := url.Parse(config.InitiateIssuanceURL)
	if err != nil {
		return fmt.Errorf("failed to parse url %w", err)
	}

	s.print("Getting issuer OIDC config")
	oidcConfig, err := s.getIssuerOIDCConfig(parsedUrl.Query().Get("issuer"))

	tokenEndpoint := oidcConfig.TokenEndpoint
	credentialsEndpoint := oidcConfig.CredentialEndpoint

	tokenValues := url.Values{
		"grant_type":          []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": []string{parsedUrl.Query().Get("pre-authorized_code")},
	}

	if strings.EqualFold(parsedUrl.Query().Get("user_pin_required"), "true") {
		if len(config.Pin) == 0 {
			log.Println("Enter PIN:")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			config.Pin = scanner.Text()
		}

		tokenValues.Add("user_pin", config.Pin)
	}

	s.print("Getting access token")
	tokenResp, tokenErr := s.httpClient.PostForm(tokenEndpoint, tokenValues)
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

	err = s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	s.print("Getting credential")
	vc, err := s.getCredential(credentialsEndpoint, config.CredentialType, config.CredentialFormat)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}

	b, err := json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	s.print("Adding credential to wallet")
	if err = s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, b); err != nil {
		return fmt.Errorf("add credential to wallet: %w", err)
	}

	log.Println("Credential added successfully")

	s.wallet.Close()

	return nil
}
