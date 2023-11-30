/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
)

var (
	ErrInteractionRestricted = errors.New("interaction restricted")
	logger                   = log.New("trustregistry")
)

type Config struct {
	HTTPClient *http.Client
}
type Service struct {
	httpClient *http.Client
}

func New(conf *Config) *Service {
	return &Service{httpClient: conf.HTTPClient}
}

// ValidateWalletPresentation validates wallet presentation using Trust Registry API.
func (s *Service) ValidateWalletPresentation(
	policyURL, verifierDID string,
	presentationCredentials []*verifiable.Credential,
) error {
	logger.Debug("ValidateWalletPresentation begin")
	walletPresentationConfig := &WalletPresentationValidationConfig{
		VerifierDID: verifierDID,
		Metadata:    make([]*CredentialMetadata, len(presentationCredentials)),
	}

	for i, credential := range presentationCredentials {
		content := credential.Contents()

		walletPresentationConfig.Metadata[i] = getTrustRegistryCredentialMetadata(content)
	}

	reqPayload, err := json.Marshal(walletPresentationConfig)
	if err != nil {
		return fmt.Errorf("encode verifier config: %w", err)
	}

	responseDecoded, err := s.doTrustRegistryRequest(context.Background(), policyURL, reqPayload)
	if err != nil {
		return err
	}

	if !responseDecoded.Allowed {
		return ErrInteractionRestricted
	}

	logger.Debug("ValidateWalletPresentation succeed")

	return nil
}

func (s *Service) doTrustRegistryRequest(ctx context.Context, policyURL string, req []byte) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	request.Header.Add("content-type", "application/json")

	resp, err := s.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var responseDecoded *Response
	err = json.NewDecoder(resp.Body).Decode(&responseDecoded)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return responseDecoded, nil
}

func getTrustRegistryCredentialMetadata(content verifiable.CredentialContents) *CredentialMetadata {
	var iss, exp string
	if content.Issued != nil {
		iss = content.Issued.FormatToString()
	}

	if content.Expired != nil {
		exp = content.Expired.FormatToString()
	}

	return &CredentialMetadata{
		CredentialID:    content.ID,
		CredentialTypes: content.Types,
		ExpirationDate:  exp,
		IssuanceDate:    iss,
		IssuerID:        content.Issuer.ID,
	}
}
