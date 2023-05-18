/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package stress

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

type TestCase struct {
	walletRunner           *walletrunner.Service
	httpClient             *http.Client
	vcsAPIURL              string
	issuerProfileID        string
	issuerProfileVersion   string
	verifierProfileID      string
	verifierProfileVersion string
	credentialTemplateID   string
	credentialType         string
	credentialFormat       string
	token                  string
	claimData              map[string]interface{}
	disableRevokeTestCase  bool
	disableVPTestCase      bool
	verifierPresentationID string
}

type TestCaseOptions struct {
	vcProviderOptions      []vcprovider.ConfigOption
	httpClient             *http.Client
	vcsAPIURL              string
	issuerProfileID        string
	issuerProfileVersion   string
	verifierProfileID      string
	credentialTemplateID   string
	credentialType         string
	credentialFormat       string
	token                  string
	claimData              map[string]interface{}
	disableRevokeTestCase  bool
	disableVPTestCase      bool
	verifierProfileVersion string
	verifierPresentationID string
}

type TestCaseOption func(opts *TestCaseOptions)

func NewTestCase(options ...TestCaseOption) (*TestCase, error) {
	opts := &TestCaseOptions{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		credentialFormat: "jwt_vc_json-ld",
	}

	for _, opt := range options {
		opt(opts)
	}

	if opts.vcsAPIURL == "" {
		return nil, fmt.Errorf("vcs api url is empty")
	}

	if opts.issuerProfileID == "" {
		return nil, fmt.Errorf("issuer profile id is empty")
	}

	if opts.verifierProfileID == "" {
		return nil, fmt.Errorf("verifier profile id is empty")
	}

	if opts.credentialType == "" {
		return nil, fmt.Errorf("credential type is empty")
	}

	runner, err := walletrunner.New(vcprovider.ProviderVCS, opts.vcProviderOptions...)
	if err != nil {
		return nil, fmt.Errorf("create wallet runner: %w", err)
	}

	return &TestCase{
		walletRunner:           runner,
		httpClient:             opts.httpClient,
		vcsAPIURL:              opts.vcsAPIURL,
		issuerProfileID:        opts.issuerProfileID,
		issuerProfileVersion:   opts.issuerProfileVersion,
		verifierProfileID:      opts.verifierProfileID,
		verifierProfileVersion: opts.verifierProfileVersion,
		credentialTemplateID:   opts.credentialTemplateID,
		credentialType:         opts.credentialType,
		credentialFormat:       opts.credentialFormat,
		token:                  opts.token,
		claimData:              opts.claimData,
		disableRevokeTestCase:  opts.disableRevokeTestCase,
		disableVPTestCase:      opts.disableVPTestCase,
		verifierPresentationID: opts.verifierPresentationID,
	}, nil
}

func WithVCProviderOption(opt vcprovider.ConfigOption) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.vcProviderOptions = append(opts.vcProviderOptions, opt)
	}
}

func WithDisableRevokeTestCase(disableRevokeTestCase bool) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.disableRevokeTestCase = disableRevokeTestCase
	}
}

func WithDisableVPTestCase(disableVpTestCase bool) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.disableVPTestCase = disableVpTestCase
	}
}

func WithHTTPClient(client *http.Client) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.httpClient = client
	}
}

func WithVCSAPIURL(apiURL string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.vcsAPIURL = apiURL
	}
}

func WithIssuerProfileID(issuerProfileID string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.issuerProfileID = issuerProfileID
	}
}

func WithIssuerProfileVersion(issuerProfileVersion string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.issuerProfileVersion = issuerProfileVersion
	}
}

func WithVerifierProfileVersion(verifierProfileVersion string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.verifierProfileVersion = verifierProfileVersion
	}
}

func WithVerifierPresentationID(presentationID string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.verifierPresentationID = presentationID
	}
}

func WithVerifierProfileID(verifierProfileID string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.verifierProfileID = verifierProfileID
	}
}

func WithCredentialTemplateID(credentialTemplateID string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.credentialTemplateID = credentialTemplateID
	}
}

func WithCredentialType(credentialType string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.credentialType = credentialType
	}
}

func WithClaimData(data map[string]interface{}) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.claimData = data
	}
}

func WithToken(token string) TestCaseOption {
	return func(opts *TestCaseOptions) {
		opts.token = token
	}
}

type stressTestPerfInfo map[string]time.Duration

func (c *TestCase) Invoke() (string, interface{}, error) {
	credentialOfferURL, pin, err := c.fetchCredentialOfferURL()
	if err != nil {
		return "", nil, fmt.Errorf("fetch credential offer url: %w", err)
	}

	// run pre-auth flow and save credential in the wallet
	credentials, err := c.walletRunner.RunOIDC4CIPreAuth(&walletrunner.OIDC4CIConfig{
		InitiateIssuanceURL: credentialOfferURL,
		CredentialType:      c.credentialType,
		CredentialFormat:    c.credentialFormat,
		Pin:                 pin,
	})

	credID := ""
	if credentials != nil {
		credID = credentials.ID
	}
	if err != nil {
		return credID, nil, fmt.Errorf("CredId [%v]. run pre-auth issuance: %w", credID, err)
	}

	providerConf := c.walletRunner.GetConfig()
	providerConf.WalletUserId = providerConf.WalletParams.UserID
	providerConf.WalletPassPhrase = providerConf.WalletParams.Passphrase
	providerConf.WalletDidID = providerConf.WalletParams.DidID[0]
	providerConf.WalletDidKeyID = providerConf.WalletParams.DidKeyID[0]
	providerConf.SkipSchemaValidation = true

	if !c.disableVPTestCase {
		authorizationRequest, err := c.fetchAuthorizationRequest()
		if err != nil {
			return credID, nil, fmt.Errorf("CredId [%v]. fetch authorization request: %w", credID, err)
		}

		err = c.walletRunner.RunOIDC4VPFlow(authorizationRequest)
		if err != nil {
			return credID, nil, fmt.Errorf("CredId [%v]. run vp: %w", credID, err)
		}
	}

	b, err := json.Marshal(c.walletRunner.GetPerfInfo())
	if err != nil {
		return credID, nil, fmt.Errorf("CredId [%v]. marshal perf info: %w", credID, err)
	}

	var perfInfo stressTestPerfInfo

	if err = json.Unmarshal(b, &perfInfo); err != nil {
		return credID, nil, fmt.Errorf("unmarshal perf info into stressTestPerfInfo: %w", err)
	}

	if !c.disableRevokeTestCase && credentials.Status != nil && credentials.Status.Type != "" {
		st := time.Now()
		if err = c.revokeVC(credentials); err != nil {
			return credID, nil, fmt.Errorf("CredId [%v]. can not revokeVc; %w", credID, err)
		}

		perfInfo["_vp_revoke_credentials"] = time.Since(st)
	}

	return credID, perfInfo, nil
}

func (c *TestCase) revokeVC(cred *verifiable.Credential) error {
	req := &model.UpdateCredentialStatusRequest{
		CredentialID: cred.ID,
		CredentialStatus: model.CredentialStatus{
			Status: "true",
			Type:   cred.Status.Type,
		},
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf("%s/issuer/profiles/%v/credentials/status",
		c.vcsAPIURL, c.issuerProfileID)

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", c.token, //nolint: bodyclose
		bytes.NewBuffer(requestBytes), &tls.Config{
			InsecureSkipVerify: true,
		})
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	return nil
}

func (c *TestCase) fetchCredentialOfferURL() (string, string, error) {
	b, err := json.Marshal(&initiateOIDC4CIRequest{
		ClaimData:            &c.claimData,
		CredentialTemplateId: c.credentialTemplateID,
		UserPinRequired:      true,
	})
	if err != nil {
		return "", "", fmt.Errorf("marshal initiate oidc4ci request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf(
			"%v/issuer/profiles/%s/%s/interactions/initiate-oidc",
			c.vcsAPIURL,
			c.issuerProfileID,
			c.issuerProfileVersion,
		),
		bytes.NewBuffer(b))
	if err != nil {
		return "", "", fmt.Errorf("create initiate oidc4ci request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("send initiate oidc4ci request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("initiate oidc4ci request failed: %v", resp.Status)
	}

	if resp.Body != nil {
		defer func() {
			err = resp.Body.Close()
			if err != nil {
				logger.Error("failed to close response body", log.WithError(err))
			}
		}()
	}

	var parsedResp initiateOIDC4CIResponse

	if err = json.NewDecoder(resp.Body).Decode(&parsedResp); err != nil {
		return "", "", fmt.Errorf("decode initiate oidc4ci response: %w", err)
	}

	pin := ""
	if parsedResp.UserPin != nil {
		pin = *parsedResp.UserPin
	}

	return parsedResp.OfferCredentialURL, pin, nil
}

func (c *TestCase) fetchAuthorizationRequest() (string, error) {
	reqData := initiateOIDC4VPData{}
	if c.verifierPresentationID != "" {
		reqData.PresentationDefinitionId = &c.verifierPresentationID
	}
	data, err := json.Marshal(reqData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf(
			"%s/verifier/profiles/%s/%s/interactions/initiate-oidc",
			c.vcsAPIURL,
			c.verifierProfileID,
			c.verifierProfileVersion,
		),
		bytes.NewBuffer(data),
	)
	if err != nil {
		return "", fmt.Errorf("create initiate oidc4vp request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", c.token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send initiate oidc4vp request: %w", err)
	}

	if resp.Body != nil {
		defer func() {
			err = resp.Body.Close()
			if err != nil {
				logger.Error("failed to close response body", log.WithError(err))
			}
		}()
	}

	respData, _ := io.ReadAll(resp.Body) //nolint
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected http status for fetchAuthorizationRequest. got %v and %v",
			resp.StatusCode, string(respData))
	}

	var parsedResp initiateOIDC4VPResponse

	if err = json.Unmarshal(respData, &parsedResp); err != nil {
		return "", fmt.Errorf("decode initiate oidc4vp response: %w", err)
	}

	return parsedResp.AuthorizationRequest, nil
}
