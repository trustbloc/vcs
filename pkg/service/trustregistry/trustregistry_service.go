/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination trustregistry_service_mocks_test.go -package trustregistry_test -source=trustregistry_service.go -mock_names httpClient=MockHTTPClient

package trustregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"go.uber.org/zap"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

const WalletAttestationVCType = "WalletAttestationCredential"

var logger = log.New("client-attestation")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config defines configuration for Service.
type Config struct {
	HTTPClient     httpClient
	DocumentLoader ld.DocumentLoader
	ProofChecker   verifiable.CombinedProofChecker
}

// Service implements attestation functionality for OAuth 2.0 Attestation-Based Client Authentication.
type Service struct {
	httpClient     httpClient
	documentLoader ld.DocumentLoader
	proofChecker   verifiable.CombinedProofChecker
}

// NewService returns a new Service instance.
func NewService(config *Config) *Service {
	return &Service{
		httpClient:     config.HTTPClient,
		documentLoader: config.DocumentLoader,
		proofChecker:   config.ProofChecker,
	}
}

// ValidateIssuance validates attestation VP and requests issuance policy evaluation.
func (s *Service) ValidateIssuance(
	ctx context.Context,
	profile *profileapi.Issuer,
	attestationVP string,
	credentialTypes []string,
) error {
	logger.Debugc(ctx, "validate issuance",
		zap.String("profileID", profile.ID),
		zap.String("profileVersion", profile.Version),
		zap.String("policyURL", profile.Checks.Policy.PolicyURL),
		zap.String("attestationVP", attestationVP),
		zap.Strings("credentialTypes", credentialTypes),
	)

	if profile.Checks.Policy.PolicyURL == "" {
		return nil
	}

	req := &IssuancePolicyEvaluationRequest{
		IssuerDID:       profile.SigningDID.DID,
		CredentialTypes: credentialTypes,
	}

	if attestationVP != "" {
		attestationVCs, err := s.parseAttestationVP(attestationVP)
		if err != nil {
			return err
		}

		req.AttestationVC = lo.ToPtr(attestationVCs)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := s.requestPolicyEvaluation(ctx, profile.Checks.Policy.PolicyURL, payload)
	if err != nil {
		return fmt.Errorf("policy evaluation: %w", err)
	}

	if !resp.Allowed {
		return ErrInteractionRestricted
	}

	return nil
}

// ValidatePresentation validates attestation VP and requests presentation policy evaluation.
//
//nolint:funlen,gocognit
func (s *Service) ValidatePresentation(
	ctx context.Context,
	profile *profileapi.Verifier,
	attestationVP string,
	metadata []CredentialMetadata,
) error {
	logger.Debugc(ctx, "validate presentation",
		zap.String("profileID", profile.ID),
		zap.String("profileVersion", profile.Version),
		zap.String("policyURL", profile.Checks.Policy.PolicyURL),
		zap.String("attestationVP", attestationVP),
	)

	if profile.Checks.Policy.PolicyURL == "" {
		return nil
	}

	req := &PresentationPolicyEvaluationRequest{
		VerifierDID:        profile.SigningDID.DID,
		CredentialMetadata: metadata,
	}

	if attestationVP != "" {
		attestationVCs, err := s.parseAttestationVP(attestationVP)
		if err != nil {
			return err
		}

		req.AttestationVC = lo.ToPtr(attestationVCs)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := s.requestPolicyEvaluation(ctx, profile.Checks.Policy.PolicyURL, payload)
	if err != nil {
		return fmt.Errorf("policy evaluation: %w", err)
	}

	if !resp.Allowed {
		return ErrInteractionRestricted
	}

	return nil
}

func (s *Service) parseAttestationVP(jwtVP string) ([]string, error) {
	attestationVP, err := verifiable.ParsePresentation(
		[]byte(jwtVP),
		// The verification of proof is conducted manually, along with an extra verification to ensure that signer of
		// the VP matches the subject of the attestation VC.
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("parse attestation vp: %w", err)
	}

	attestationVCs := make([]string, 0)

	for _, vc := range attestationVP.Credentials() {
		if !lo.Contains(vc.Contents().Types, WalletAttestationVCType) {
			continue
		}

		// validate attestation VC
		credentialOpts := []verifiable.CredentialOpt{
			verifiable.WithProofChecker(s.proofChecker),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader),
		}

		if err = vc.ValidateCredential(credentialOpts...); err != nil {
			return nil, fmt.Errorf("validate attestation vc: %w", err)
		}

		if err = vc.CheckProof(credentialOpts...); err != nil {
			return nil, fmt.Errorf("check attestation vc proof: %w", err)
		}

		vcc := vc.Contents()

		if vcc.Expired != nil && time.Now().UTC().After(vcc.Expired.Time) {
			return nil, fmt.Errorf("attestation vc is expired")
		}

		// validate vp proof with extra check for wallet binding
		if err = jwt.CheckProof(jwtVP, s.proofChecker, &vcc.Subject[0].ID, nil); err != nil {
			return nil, fmt.Errorf("check attestation vp proof: %w", err)
		}

		jwtVC, marshalErr := vc.ToJWTString()
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal attestation vc to jwt: %w", marshalErr)
		}

		attestationVCs = append(attestationVCs, jwtVC)
	}

	return attestationVCs, nil
}

func (s *Service) requestPolicyEvaluation(
	ctx context.Context,
	policyURL string,
	payload []byte,
) (*PolicyEvaluationResponse, error) {
	logger.Debugc(ctx, "request policy evaluation",
		zap.String("url", policyURL),
		zap.String("payload", string(payload)),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("content-type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status code: %d, msg: %s", resp.StatusCode, string(b))
	}

	var result *PolicyEvaluationResponse

	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}
