/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package revocation

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"

	"github.com/trustbloc/vcs/internal/pkg/log"
)

var logger = log.New("vcs-revocation-service")

const (
	cslRequestTokenName = "csl"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	VDR            vdrapi.Registry
	TLSConfig      *tls.Config
	RequestTokens  map[string]string
	DocumentLoader ld.DocumentLoader
}

// Service is responsible for calling credentialstatus.Service .GetRevocationListVC() via HTTP.
type Service struct {
	vdr            vdrapi.Registry
	httpClient     httpClient
	requestTokens  map[string]string
	documentLoader ld.DocumentLoader
}

func New(config *Config) *Service {
	return &Service{
		vdr:            config.VDR,
		httpClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:  config.RequestTokens,
		documentLoader: config.DocumentLoader,
	}
}

// GetRevocationVC returns revocation VC identified by statusURI.
// statusURI might be either HTTP URL or DID URL.
func (s *Service) GetRevocationVC(statusURI string) (*verifiable.Credential, error) {
	var vcBytes []byte
	var err error
	switch {
	case strings.HasPrefix(statusURI, "did:"):
		vcBytes, err = s.resolveDIDRelativeURL(statusURI)
	default:
		vcBytes, err = s.resolveHTTPUrl(statusURI)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to resolve revocation VC URI: %w", err)
	}

	revocationListVC, err := s.parseAndVerifyVC(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	return revocationListVC, nil
}

func (s *Service) resolveHTTPUrl(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.sendHTTPRequest(req, http.StatusOK, s.requestTokens[cslRequestTokenName])
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Service) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	return verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	)
}

func (s *Service) sendHTTPRequest(req *http.Request, status int, token string) ([]byte, error) {
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warn("failed to close response body")
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("Unable to read response", log.WithHTTPStatus(resp.StatusCode), log.WithError(err))
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
