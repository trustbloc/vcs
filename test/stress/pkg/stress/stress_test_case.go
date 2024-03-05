/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package stress

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/legacy/mem"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/method/web"
	"github.com/trustbloc/did-go/vdr"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	"github.com/trustbloc/logutil-go/pkg/log"
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vci"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vp"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

const (
	attestationServiceURL = "https://mock-attestation.trustbloc.local:8097/profiles/profileID/profileVersion/wallet/attestation"
	trustRegistryHost     = "https://mock-trustregistry.trustbloc.local:8098"
)

type TestCase struct {
	oidc4vciProvider       *oidc4vciProvider
	oidc4vpProvider        *oidc4vpProvider
	wallet                 *wallet.Wallet
	httpClient             *http.Client
	vcsAPIURL              string
	issuerProfileID        string
	issuerProfileVersion   string
	verifierProfileID      string
	verifierProfileVersion string
	credentialTemplateID   string
	credentialType         string
	oidcCredentialFormat   vcsverifiable.OIDCFormat
	token                  string
	claimData              map[string]interface{}
	disableRevokeTestCase  bool
	disableVPTestCase      bool
	verifierPresentationID string
}

type TestCaseOptions struct {
	httpClient             *http.Client
	vcsAPIURL              string
	issuerProfileID        string
	issuerProfileVersion   string
	verifierProfileID      string
	credentialTemplateID   string
	credentialType         string
	oidcCredentialFormat   vcsverifiable.OIDCFormat
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
		oidcCredentialFormat: vcsverifiable.JwtVCJsonLD,
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

	documentLoader, err := bddutil.DocumentLoader()
	if err != nil {
		return nil, fmt.Errorf("init document loader: %w", err)
	}

	longForm, err := longform.New()
	if err != nil {
		return nil, fmt.Errorf("init ion vdr: %w", err)
	}

	vdRegistry := vdr.New(
		vdr.WithVDR(longForm),
		vdr.WithVDR(key.New()),
		vdr.WithVDR(jwk.New()),
		vdr.WithVDR(
			&webVDR{
				httpClient: opts.httpClient,
				VDR:        web.New(),
			},
		),
	)

	storageProvider := mem.NewProvider()

	kmsStore, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("init kms store: %w", err)
	}

	suite, err := localsuite.NewLocalCryptoSuite("local-lock://wallet-cli", kmsStore, &noop.NoLock{})
	if err != nil {
		return nil, fmt.Errorf("init local crypto suite: %w", err)
	}

	keyCreator, err := suite.RawKeyCreator()
	if err != nil {
		return nil, fmt.Errorf("init key creator: %w", err)
	}

	w, err := wallet.New(
		&walletProvider{
			storageProvider: storageProvider,
			documentLoader:  documentLoader,
			vdRegistry:      vdRegistry,
			keyCreator:      keyCreator,
		},
		wallet.WithNewDID("ion"),
		wallet.WithKeyType("ECDSAP384DER"),
	)
	if err != nil {
		return nil, fmt.Errorf("init wallet: %w", err)
	}

	wellKnownService := &wellknown.Service{
		HTTPClient:  opts.httpClient,
		VDRRegistry: vdRegistry,
	}

	attestationService, err := attestation.NewService(
		&attestationProvider{
			storageProvider: storageProvider,
			httpClient:      opts.httpClient,
			documentLoader:  documentLoader,
			cryptoSuite:     suite,
			wallet:          w,
		},
		attestationServiceURL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("create attestation service: %w", err)
	}

	trustRegistry := trustregistry.NewClient(opts.httpClient, trustRegistryHost)

	return &TestCase{
		oidc4vciProvider: &oidc4vciProvider{
			storageProvider:    storageProvider,
			httpClient:         opts.httpClient,
			documentLoader:     documentLoader,
			vdrRegistry:        vdRegistry,
			cryptoSuite:        suite,
			attestationService: attestationService,
			trustRegistry:      trustRegistry,
			wallet:             w,
			wellKnownService:   wellKnownService,
		},
		oidc4vpProvider: &oidc4vpProvider{
			storageProvider:    storageProvider,
			httpClient:         opts.httpClient,
			documentLoader:     documentLoader,
			vdrRegistry:        vdRegistry,
			cryptoSuite:        suite,
			attestationService: attestationService,
			trustRegistry:      trustRegistry,
			wallet:             w,
		},
		wallet:                 w,
		httpClient:             opts.httpClient,
		vcsAPIURL:              opts.vcsAPIURL,
		issuerProfileID:        opts.issuerProfileID,
		issuerProfileVersion:   opts.issuerProfileVersion,
		verifierProfileID:      opts.verifierProfileID,
		verifierProfileVersion: opts.verifierProfileVersion,
		credentialTemplateID:   opts.credentialTemplateID,
		credentialType:         opts.credentialType,
		oidcCredentialFormat:   opts.oidcCredentialFormat,
		token:                  opts.token,
		claimData:              opts.claimData,
		disableRevokeTestCase:  opts.disableRevokeTestCase,
		disableVPTestCase:      opts.disableVPTestCase,
		verifierPresentationID: opts.verifierPresentationID,
	}, nil
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
	vciFlow, err := oidc4vci.NewFlow(c.oidc4vciProvider,
		oidc4vci.WithFlowType(oidc4vci.FlowTypePreAuthorizedCode),
		oidc4vci.WithCredentialOffer(credentialOfferURL),
		oidc4vci.WithCredentialType(c.credentialType),
		oidc4vci.WithOIDCCredentialFormat(c.oidcCredentialFormat),
		oidc4vci.WithPin(pin),
	)
	if err != nil {
		return "", nil, fmt.Errorf("init pre-auth flow: %w", err)
	}

	credentials, err := vciFlow.Run(context.Background())
	if err != nil {
		return "", nil, fmt.Errorf("run pre-auth flow: %w", err)
	}

	credID := ""

	if credentials != nil {
		credID = credentials.Contents().ID
	}

	if err != nil {
		return credID, nil, fmt.Errorf("cred id [%v]; run pre-auth issuance: %w", credID, err)
	}

	perfInfo := make(stressTestPerfInfo)

	if !c.disableVPTestCase {
		var (
			authorizationRequest string
			vpFlow               *oidc4vp.Flow
			b                    []byte
		)

		authorizationRequest, err = c.fetchAuthorizationRequest()
		if err != nil {
			return credID, nil, fmt.Errorf("cred id [%v]; fetch authorization request: %w", credID, err)
		}

		vpFlow, err = oidc4vp.NewFlow(c.oidc4vpProvider,
			oidc4vp.WithRequestURI(strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")),
			oidc4vp.WithDomainMatchingDisabled(),
			oidc4vp.WithSchemaValidationDisabled(),
		)
		if err != nil {
			return "", nil, fmt.Errorf("cred id [%v]; init flow: %w", credID, err)
		}

		if err = vpFlow.Run(context.Background()); err != nil {
			return "", nil, fmt.Errorf("cred id [%v]; run vp flow: %w", credID, err)
		}

		var vpPerfInfo map[string]time.Duration

		b, err = json.Marshal(vpFlow.PerfInfo())
		if err != nil {
			return credID, nil, fmt.Errorf("cred id [%v]; marshal vp perf info: %w", credID, err)
		}

		if err = json.Unmarshal(b, &vpPerfInfo); err != nil {
			return credID, nil, fmt.Errorf("unmarshal vp perf info into stressTestPerfInfo: %w", err)
		}

		for k, v := range vpPerfInfo {
			perfInfo[k] = v
		}
	}

	var vciPerfInfo map[string]time.Duration

	b, err := json.Marshal(vciFlow.PerfInfo())
	if err != nil {
		return credID, nil, fmt.Errorf("cred id [%v]; marshal vci perf info: %w", credID, err)
	}

	if err = json.Unmarshal(b, &vciPerfInfo); err != nil {
		return credID, nil, fmt.Errorf("unmarshal vci perf info into stressTestPerfInfo: %w", err)
	}

	for k, v := range vciPerfInfo {
		perfInfo[k] = v
	}

	if !c.disableRevokeTestCase && credentials.Contents().Status != nil && credentials.Contents().Status.Type != "" {
		st := time.Now()
		if err = c.revokeVC(credentials); err != nil {
			return credID, nil, fmt.Errorf("cred id [%v]; can not revokeVc; %w", credID, err)
		}

		perfInfo["_vp_revoke_credentials"] = time.Since(st)
	}

	return credID, perfInfo, nil
}

func (c *TestCase) revokeVC(cred *verifiable.Credential) error {
	req := &model.UpdateCredentialStatusRequest{
		CredentialID: cred.Contents().ID,
		CredentialStatus: model.CredentialStatus{
			Status: "true",
			Type:   cred.Contents().Status.Type,
		},
		ProfileID:      c.issuerProfileID,
		ProfileVersion: c.issuerProfileVersion,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	endpointURL := fmt.Sprintf("%s/issuer/credentials/status", c.vcsAPIURL)

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

	if resp.Body != nil {
		defer func() {
			err = resp.Body.Close()
			if err != nil {
				logger.Error("failed to close response body", log.WithError(err))
			}
		}()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint
		return "", "", fmt.Errorf("initiate oidc4ci request failed: %v; response: %s", resp.Status, string(body))
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

type attestationProvider struct {
	storageProvider storageapi.Provider
	httpClient      *http.Client
	documentLoader  ld.DocumentLoader
	cryptoSuite     api.Suite
	wallet          *wallet.Wallet
}

func (p *attestationProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *attestationProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *attestationProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *attestationProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *attestationProvider) Wallet() *wallet.Wallet {
	return p.wallet
}
