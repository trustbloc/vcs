/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
)

type TestCase struct {
	walletRunner *walletrunner.Service
	httpClient   *http.Client
	config       *TestCaseConfig
	walletFileDB string
}

type TestCaseConfig struct {
	DemoIssuerURL            string
	DemoVerifierGetQRCodeURL string
	ContextProviderURL       string
	DIDKeyType               string
	DIDMethod                string
	CredentialType           string
	CredentialFormat         string
}

func NewTestCase(config *TestCaseConfig) (*TestCase, func(), error) {
	walletFileDB, err := os.CreateTemp("", "wallet-*.db")
	if err != nil {
		return nil, func() {}, fmt.Errorf("create wallet file db: %w", err)
	}

	cleanup := func() {
		_ = os.Remove(walletFileDB.Name())
	}

	runner, err := walletrunner.New(vcprovider.ProviderVCS,
		func(c *vcprovider.Config) {
			c.ContextProviderURL = config.ContextProviderURL
			c.DidKeyType = config.DIDKeyType
			c.DidMethod = config.DIDMethod
			c.StorageProvider = "leveldb"
			c.StorageProviderConnString = walletFileDB.Name()
			c.InsecureTls = true
		},
	)
	if err != nil {
		cleanup()
		return nil, cleanup, fmt.Errorf("create wallet runner: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return &TestCase{
		walletRunner: runner,
		httpClient:   httpClient,
		config:       config,
	}, cleanup, nil
}

type stressTestPerfInfo struct {
	PreAuthFlowTime int64
	VPFlowTime      int64
}

func (c *TestCase) Invoke() (interface{}, error) {
	perfInfo := stressTestPerfInfo{}

	initiateIssuanceURL, pin, err := c.fetchInitiateIssuanceURL(c.config.DemoIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("fetch initiate issuance url: %w", err)
	}

	startTime := time.Now()

	// run pre-auth flow and save credential in the wallet
	if err = c.walletRunner.RunOIDC4CIPreAuth(&walletrunner.OIDC4CIConfig{
		InitiateIssuanceURL: initiateIssuanceURL,
		CredentialType:      c.config.CredentialType,
		CredentialFormat:    c.config.CredentialFormat,
		Pin:                 pin,
	}); err != nil {
		return nil, fmt.Errorf("run pre-auth issuance: %w", err)
	}

	perfInfo.PreAuthFlowTime = time.Since(startTime).Milliseconds()

	providerConf := c.walletRunner.GetConfig()
	providerConf.WalletUserId = providerConf.WalletParams.UserID
	providerConf.WalletPassPhrase = providerConf.WalletParams.Passphrase
	providerConf.WalletDidID = providerConf.WalletParams.DidID
	providerConf.WalletDidKeyID = providerConf.WalletParams.DidKeyID
	providerConf.SkipSchemaValidation = true

	authorizationRequest, err := c.fetchAuthorizationRequest(c.config.DemoVerifierGetQRCodeURL)
	if err != nil {
		return nil, fmt.Errorf("fetch authorization request: %w", err)
	}

	startTime = time.Now()

	err = c.walletRunner.RunOIDC4VPFlow(authorizationRequest)
	if err != nil {
		return nil, fmt.Errorf("run vp: %w", err)
	}

	perfInfo.VPFlowTime = time.Since(startTime).Milliseconds()

	return perfInfo, nil
}

func (c *TestCase) fetchInitiateIssuanceURL(demoIssuerURL string) (string, string, error) {
	resp, err := c.httpClient.Get(demoIssuerURL)
	if err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	_ = resp.Body.Close()

	parsedURL := string(body)
	r := regexp.MustCompile(`(openid-initiate-issuance://\?[^<]+)`)
	parsedURL = r.FindString(parsedURL)
	parsedURL, err = url.QueryUnescape(parsedURL)
	parsedURL = strings.ReplaceAll(parsedURL, "&amp;", "&")

	if parsedURL == "" {
		return "", "", fmt.Errorf("initiate issuance url not found")
	}

	pin := ""
	pinGroups := regexp.MustCompile(`<div id="pin">([^<]+)`).FindAllStringSubmatch(string(body), -1)
	if len(pinGroups) == 1 {
		if len(pinGroups[0]) == 2 {
			pin = pinGroups[0][1]
		}
	}

	return parsedURL, pin, nil
}

type GetQRCodeResponse struct {
	QRText string `json:"qrText"`
	TxID   string `json:"txID"`
}

func (c *TestCase) fetchAuthorizationRequest(qrCodeURL string) (string, error) {
	resp, err := c.httpClient.Get(qrCodeURL)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}

	var qrCodeResp GetQRCodeResponse

	if err = json.NewDecoder(resp.Body).Decode(&qrCodeResp); err != nil {
		return "", err
	}

	return qrCodeResp.QRText, nil
}
