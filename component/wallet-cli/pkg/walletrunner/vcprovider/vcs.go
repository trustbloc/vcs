/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/httputil"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/ldutil"
	"github.com/trustbloc/vcs/component/wallet-cli/internal/oauth2util"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

const (
	ProviderVCS = "vcs"

	didDomain           = "https://testnet.orb.local"
	didServiceAuthToken = "tk1"
	oidcProviderURL     = "https://localhost:4444"
	issueCredentialURL  = "https://api-gateway.trustbloc.local:5566/issuer/profiles/i_myprofile_ud_es256_jwt/latest/credentials/issue"
	testDataPath        = "testdata/vcs"
)

// defaultVCSLocalConfig returns default *Config for VCS that refers to the local containers.
func defaultVCSLocalConfig() *Config {
	return &Config{
		TLS: &tls.Config{
			InsecureSkipVerify: true,
		},
		WalletParams:        &WalletParams{},
		ContextProviderURL:  "",
		OidcProviderURL:     oidcProviderURL,
		IssueVCURL:          issueCredentialURL,
		DidDomain:           didDomain,
		DidServiceAuthToken: didServiceAuthToken,
		VCFormat:            vcsverifiable.JwtVCJsonLD,
		OrgName:             "test_org",
		OrgSecret:           "test-org-secret",
		DidKeyType:          kms.ED25519,
		DidMethod:           "ion",
		WalletDidCount:      1,
	}
}

type vcsCredentialsProvider struct {
	conf *Config
}

func newVCSCredentialsProvider(opts ...ConfigOption) *vcsCredentialsProvider {
	conf := defaultVCSLocalConfig()

	for _, f := range opts {
		f(conf)
	}

	return &vcsCredentialsProvider{
		conf: conf,
	}
}

func (p *vcsCredentialsProvider) GetConfig() *Config {
	return p.conf
}

func (p *vcsCredentialsProvider) GetCredentials() (map[string][]byte, error) {
	testData := map[string][]byte{}

	token, err := p.authorizeOrganization(p.conf.OrgName, p.conf.OrgSecret)
	if err != nil {
		return nil, fmt.Errorf("error creating oauth token: %w", err)
	}

	files, err := os.ReadDir(testDataPath)
	if err != nil {
		return nil, fmt.Errorf("error reading tesdata dir: %w", err)
	}

	for _, file := range files {
		var vcData []byte
		vcData, err = os.ReadFile(filepath.Join(testDataPath, file.Name())) //nolint: gosec
		if err != nil {
			return nil, fmt.Errorf("error read VC file: %w", err)
		}

		vcData, err = p.createVCSCredential(string(vcData), token)
		if err != nil {
			return nil, err
		}

		testData[file.Name()] = vcData
	}

	return testData, nil
}

func (p *vcsCredentialsProvider) authorizeOrganization(clientID, secret string) (string, error) {
	accessToken, err := oauth2util.Token(context.Background(), p.conf.OidcProviderURL,
		clientID, secret, []string{"org_admin"}, p.conf.TLS)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (p *vcsCredentialsProvider) createVCSCredential(credential, authToken string) ([]byte, error) {
	loader, err := ldutil.DocumentLoader()
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	cred, err := verifiable.ParseCredential([]byte(credential),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return nil, fmt.Errorf("err parsing credentials: %w", err)
	}

	cred.ID = uuid.New().URN()

	subjs, ok := cred.Subject.([]verifiable.Subject)
	if !ok {
		return nil, fmt.Errorf("cred subject has wrong type, not verifiable.Subject")
	}

	subjs[0].ID = p.conf.WalletParams.DidID[0]

	reqData, err := GetIssueCredentialRequestData(cred, p.conf.VCFormat)
	if err != nil {
		return nil, fmt.Errorf("unable to get issue credential request data: %w", err)
	}

	req := &issuerv1.IssueCredentialData{
		Credential: &reqData,
	}

	requestBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := httputil.HTTPSDo(http.MethodPost, p.conf.IssueVCURL, "application/json", authToken, //nolint: bodyclose
		bytes.NewBuffer(requestBytes), p.conf.TLS)
	if err != nil {
		return nil, err
	}

	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return respBytes, nil
}

func GetIssueCredentialRequestData(vc *verifiable.Credential, desiredFormat vcsverifiable.OIDCFormat) (interface{}, error) {
	switch desiredFormat {
	case vcsverifiable.JwtVCJsonLD, vcsverifiable.JwtVCJson:
		claims, err := vc.JWTClaims(false)
		if err != nil {
			return nil, err
		}

		return claims.MarshalUnsecuredJWT()
	case vcsverifiable.LdpVC:
		return vc, nil

	default:
		return nil, fmt.Errorf("unsupported format %s", desiredFormat)
	}
}
