/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package trustregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/samber/lo"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"
)

var (
	ErrInteractionRestricted = errors.New("interaction restricted")
	logger                   = log.New("trustregistry")
)

const (
	walletAttestationVCType = "WalletAttestationCredential"
)

type Service struct {
	url        string
	httpClient *http.Client
}

type Config struct {
	TrustRegistryURL string
	HTTPClient       *http.Client
}

func New(conf *Config) *Service {
	return &Service{
		url:        conf.TrustRegistryURL,
		httpClient: conf.HTTPClient,
	}
}

func (s *Service) ValidateVerifier(verifierDID string, presentationCredentials []*verifiable.Credential) error {
	logger.Debug("ValidateVerifier begin")
	verifierValidationConfig := &VerifierValidationConfig{
		VerifierDID: verifierDID,
		Metadata:    make([]*CredentialMetadata, len(presentationCredentials)),
	}

	for i, credential := range presentationCredentials {
		content := credential.Contents()

		verifierValidationConfig.Metadata[i] = s.getCredentialMetadata(content)
	}

	req, err := json.Marshal(verifierValidationConfig)
	if err != nil {
		return fmt.Errorf("encode verifier config: %w", err)
	}

	responseDecoded, err := s.doRequest(req)
	if err != nil {
		return err
	}

	if !responseDecoded.Allowed {
		return ErrInteractionRestricted
	}

	logger.Debug("ValidateVerifier succeed")

	return nil
}

func (s *Service) ValidatePresentation(policyID string, presentationCredentials []*verifiable.Credential) error {
	logger.Debug("ValidatePresentation begin")

	presentationValidationConfig := &PresentationValidationConfig{
		PolicyID: policyID,
		Metadata: make([]*CredentialMetadata, len(presentationCredentials)),
	}

	for i, credential := range presentationCredentials {
		content := credential.Contents()

		if lo.Contains(content.Types, walletAttestationVCType) {
			attestationVC, err := credential.ToUniversalForm()
			if err == nil {
				presentationValidationConfig.AttestationVC = attestationVC
			}
		}

		presentationValidationConfig.Metadata[i] = s.getCredentialMetadata(content)
	}

	req, err := json.Marshal(presentationValidationConfig)
	if err != nil {
		return fmt.Errorf("encode presentation config: %w", err)
	}

	responseDecoded, err := s.doRequest(req)
	if err != nil {
		return err
	}

	if !responseDecoded.Allowed {
		return ErrInteractionRestricted
	}

	logger.Debug("ValidatePresentation succeed")

	return nil
}

func (s *Service) doRequest(req []byte) (*Response, error) {
	resp, err := s.httpClient.Post(s.url, "application/json", bytes.NewReader(req)) //nolint:noctx
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

func (s *Service) getCredentialMetadata(content verifiable.CredentialContents) *CredentialMetadata {
	var iss, exp string
	if content.Issued != nil {
		iss = content.Issued.FormatToString()
	}

	if content.Expired != nil {
		exp = content.Expired.FormatToString()
	}

	return &CredentialMetadata{
		CredentialID: content.ID,
		Types:        content.Types,
		Issuer:       content.Issuer.ID,
		Issued:       iss,
		Expired:      exp,
	}
}
