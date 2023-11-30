/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/trustbloc/vc-go/verifiable"
)

var (
	ErrInteractionRestricted = errors.New("interaction restricted")
)

const (
	walletAttestationVCType = "WalletAttestationCredential"
)

// TODO: update payloads
func IssuerInteractionTrustRegistryPayloadBuilder(
	_ string,
	attestationVC *verifiable.Credential,
	presentation *verifiable.Presentation,
) ([]byte, error) {
	credentials := presentation.Credentials()

	presentationValidationConfig := &IssuerInteractionValidationConfig{
		Metadata: make([]*CredentialMetadata, len(credentials)),
	}

	if uf, err := attestationVC.ToUniversalForm(); err == nil {
		presentationValidationConfig.AttestationVC = uf
	}

	for i, credential := range credentials {
		content := credential.Contents()

		presentationValidationConfig.Metadata[i] = getCredentialMetadata(content)
	}

	reqPayload, err := json.Marshal(presentationValidationConfig)
	if err != nil {
		return nil, fmt.Errorf("encode presentation config: %w", err)
	}

	return reqPayload, nil
}

// VerifierInteractionTrustRegistryPayloadBuilder builds Trust Registry payload for Verifier interaction verification.
func VerifierInteractionTrustRegistryPayloadBuilder(
	verifierDID string,
	attestationVC *verifiable.Credential,
	presentation *verifiable.Presentation,
) ([]byte, error) {
	credentials := presentation.Credentials()

	presentationValidationConfig := &VerifierPresentationValidationConfig{
		AttestationVC:       make([]string, 1),
		VerifierDID:         verifierDID,
		RequestedVCMetadata: make([]*CredentialMetadata, len(credentials)),
	}

	if attestationVCJWT, err := attestationVC.ToJWTString(); err == nil {
		presentationValidationConfig.AttestationVC[0] = attestationVCJWT
	}

	for i, credential := range credentials {
		content := credential.Contents()

		presentationValidationConfig.RequestedVCMetadata[i] = getCredentialMetadata(content)
	}

	reqPayload, err := json.Marshal(presentationValidationConfig)
	if err != nil {
		return nil, fmt.Errorf("encode presentation config: %w", err)
	}

	return reqPayload, nil
}

func (s *Service) doTrustRegistryRequest(
	ctx context.Context, policyURL string, req []byte) (*TrustRegistryResponse, error) {
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

	var responseDecoded *TrustRegistryResponse
	err = json.NewDecoder(resp.Body).Decode(&responseDecoded)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return responseDecoded, nil
}

func getCredentialMetadata(content verifiable.CredentialContents) *CredentialMetadata {
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
		IssuerID:     content.Issuer.ID,
		Issued:       iss,
		Expired:      exp,
	}
}
