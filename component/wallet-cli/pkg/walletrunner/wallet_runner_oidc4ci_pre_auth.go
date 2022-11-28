/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
)

func (s *Service) RunOIDC4CIPreAuth(config *OIDC4CIConfig) error {
	log.Println("Start OIDC4CI-PreAuthorize flow")

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// tood debug
	resp, err := httpClient.Get("https://demo-issuer.stg.trustbloc.dev/pre-authorize")
	if err != nil {
		return err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	r := regexp.MustCompile(`(openid-initiate-issuance://\?[^<]+)`)
	config.InitiateIssuanceURL = r.FindString(string(data))
	config.InitiateIssuanceURL, err = url.QueryUnescape(config.InitiateIssuanceURL)
	config.InitiateIssuanceURL = strings.ReplaceAll(config.InitiateIssuanceURL, "&amp;", "&")
	if err != nil {
		return err
	}
	// end debug

	parsedUrl, err := url.Parse(config.InitiateIssuanceURL)
	if err != nil {
		return fmt.Errorf("failed to parse url %w", err)
	}

	fmt.Println(parsedUrl.Query())

	issuerUrl := parsedUrl.Query().Get("issuer")
	wellKnownUrl, _ := url.JoinPath(issuerUrl, ".well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("failed to create wellKnownUrl %w", err)
	}

	log.Println("Well known url is " + wellKnownUrl)

	resp, err = httpClient.Get(wellKnownUrl)
	if err != nil {
		return err
	}

	var wellKnown map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return err
	}

	// todo check if pin required
	tokenEndpoint := wellKnown["token_endpoint"].(string)
	log.Println("Token url is" + tokenEndpoint)

	tokenResp, tokenErr := httpClient.PostForm(tokenEndpoint, url.Values{
		"grant_type":          []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": []string{parsedUrl.Query().Get("pre-authorized_code")},
		"user_pin":            []string{"1234"},
	})
	//b, _ := io.ReadAll(tokenResp.Body)
	//fmt.Println(string(b))
	if tokenErr != nil {
		return tokenErr
	}

	var token oidc4ci.AccessTokenResponse
	if err = json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		return err
	}
	_ = tokenResp.Body.Close()

	log.Println("Creating wallet")
	err = s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	proofValue, err := s.createProof(
		"oidc4vc_client", // todo dynamic client registration
		*token.CNonce,
		s.vcProviderConf.WalletParams.DidKeyID,
	)
	if err != nil {
		return err
	}

	fmt.Println(proofValue)

	s.wallet.Close()

	return nil
}

func (s *Service) createProof(
	clientId string,
	cNonce string,
	verificationKID string,
) (string, error) {
	//jwtHeaders := map[string]interface{}{
	//	"alg": "EdDSA",
	//	"kid": verificationKID,
	//}

	sign, err := signToken(map[string]interface{}{
		"iss":   clientId,
		"iat":   time.Now().Unix(),
		"nonce": cNonce,
	}, s.vcProviderConf.WalletParams.DidKeyID, s.ariesServices.crypto, s.ariesServices.kms)
	if err != nil {
		return "", err
	}

	return sign, nil
	//
	//s.ariesServices.KMS()
	//ww := s.wallet
	//fmt.Println(ww)
	//s.CreateWallet()
	//keyPair, err := s.wallet.CreateKeyPair(s.vcProviderConf.WalletParams.Token, kms.ED25519)
	//if err != nil {
	//	return "", err
	//}
	//fmt.Println(keyPair)
	//keyId, _, err := s.ariesServices.KMS().CreateAndExportPubKeyBytes(kms.ED25519)
	//if err != nil {
	//	return "", err
	//}
	//
	//keyHandle, err := s.ariesServices.kms.Get(keyId)
	//if err != nil {
	//	return "", err
	//}
	//
	////keyHandle, err := s.ariesServices.kms.Get(keyPair.KeyID)
	////if err != nil {
	////	return "", err
	////}
	////
	////jsonToken := jwt.JSONWebToken{
	////	Headers: jwtHeaders,
	////	Payload:
	////}
	//
	//payload, err := json.Marshal(map[string]interface{}{
	//	"iss":   clientId,
	//	"iat":   time.Now().Unix(),
	//	"nonce": cNonce,
	//})
	//if err != nil {
	//	return "", err
	//}
	//
	//signed, err := s.ariesServices.crypto.Sign(payload, keyHandle)
	//fmt.Println(string(signed))
	//if err != nil {
	//	return "", err
	//}
	//
	//fmt.Println(string(signed))
	//
	//return string(signed), nil
}
