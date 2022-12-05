/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/samber/lo"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
)

func (s *Service) RunOIDC4CIPreAuth(config *OIDC4CIConfig) error {
	log.Println("Start OIDC4CI-PreAuthorize flow")

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	parsedUrl, err := url.Parse(config.InitiateIssuanceURL)
	if err != nil {
		return fmt.Errorf("failed to parse url %w", err)
	}

	log.Println("Getting issuer OIDC config from well-known endpoint")
	oidcConfig, err := s.getIssuerOIDCConfig(parsedUrl.Query().Get("issuer"))

	tokenEndpoint := oidcConfig.TokenEndpoint
	credentialsEndpoint := oidcConfig.CredentialEndpoint

	log.Println("Token url is" + tokenEndpoint)
	log.Println("Credentials url is" + credentialsEndpoint)

	tokenValues := url.Values{
		"grant_type":          []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": []string{parsedUrl.Query().Get("pre-authorized_code")},
	}

	if strings.EqualFold(parsedUrl.Query().Get("user_pin_required"), "true") {
		if len(config.Pin) == 0 {
			log.Println("Please enter PIN for pre-authorized flow (after this press enter):")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			config.Pin = scanner.Text()
		}

		log.Println("using PIN: " + config.Pin)
		tokenValues.Add("user_pin", config.Pin)
	}

	tokenResp, tokenErr := httpClient.PostForm(tokenEndpoint, tokenValues)
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

	log.Println("Creating wallet")
	err = s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	log.Println("Getting credential")
	vc, err := s.getCredential(credentialsEndpoint, config.CredentialType, config.CredentialFormat)
	if err != nil {
		return fmt.Errorf("get credential: %w", err)
	}

	b, err := json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal vc: %w", err)
	}

	log.Println("Adding credential to wallet")
	if err = s.wallet.Add(s.vcProviderConf.WalletParams.Token, wallet.Credential, b); err != nil {
		return fmt.Errorf("add credential to wallet: %w", err)
	}
	log.Println("Credentials added successfully")

	s.wallet.Close()

	return nil
}
