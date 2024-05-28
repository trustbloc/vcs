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

var _ ServiceInterface = (*Service)(nil)

var logger = log.New("client-attestation")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config defines dependencies for Service.
type Config struct {
	HTTPClient     httpClient
	DocumentLoader ld.DocumentLoader
	ProofChecker   verifiable.CombinedProofChecker
}

// Service requests policy evaluation from Trust Registry to validate that the wallet has satisfied
// attestation requirements.
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
	data *ValidateIssuanceData,
) error {
	logger.Debugc(ctx, "validate issuance",
		zap.String("profileID", profile.ID),
		zap.String("profileVersion", profile.Version),
		zap.String("policyURL", profile.Checks.Policy.PolicyURL),
		zap.String("attestationVP", data.AttestationVP),
		zap.Strings("credentialTypes", data.CredentialTypes),
	)

	if profile.Checks.Policy.PolicyURL == "" {
		return nil
	}

	req := &IssuancePolicyEvaluationRequest{
		IssuerDID:       profile.SigningDID.DID,
		CredentialTypes: removeDuplicates(data.CredentialTypes),
	}

	if data.AttestationVP != "" {
		if err := verifyAudience(data.AttestationVP, profile.SigningDID.DID); err != nil {
			return fmt.Errorf("verify audience: %w", err)
		}

		attestationVCs, err := s.parseAttestationVP(data.AttestationVP, data.Nonce, true)
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
		if resp.DenyReasons != nil && len(*resp.DenyReasons) > 0 {
			return fmt.Errorf("%w: %s", ErrInteractionRestricted, lo.FromPtr(resp.DenyReasons))
		}

		return ErrInteractionRestricted
	}

	return nil
}

func verifyAudience(jwtVP string, issuerDID string) error {
	token, _, err := jwt.Parse(jwtVP)
	if err != nil {
		return fmt.Errorf("parse jwt: %w", err)
	}

	var claims verifiable.JWTCredClaims

	if err = token.DecodeClaims(&claims); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	if !claims.Audience.Contains(issuerDID) {
		return fmt.Errorf("invalid audience")
	}

	return nil
}

// ValidatePresentation validates attestation VP and requests presentation policy evaluation.
//
//nolint:funlen,gocognit
func (s *Service) ValidatePresentation(
	ctx context.Context,
	profile *profileapi.Verifier,
	data *ValidatePresentationData,
) error {
	logger.Debugc(ctx, "validate presentation",
		zap.String("profileID", profile.ID),
		zap.String("profileVersion", profile.Version),
		zap.String("policyURL", profile.Checks.Policy.PolicyURL),
		zap.String("attestationVP", data.AttestationVP),
	)

	if profile.Checks.Policy.PolicyURL == "" {
		return nil
	}

	req := &PresentationPolicyEvaluationRequest{
		VerifierDID:       profile.SigningDID.DID,
		CredentialMatches: data.CredentialMatches,
	}

	if data.AttestationVP != "" {
		attestationVCs, err := s.parseAttestationVP(data.AttestationVP, "", false)
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
		if resp.DenyReasons != nil && len(*resp.DenyReasons) > 0 {
			return fmt.Errorf("%w: %s", ErrInteractionRestricted, lo.FromPtr(resp.DenyReasons))
		}

		return ErrInteractionRestricted
	}

	return nil
}

func (s *Service) parseAttestationVP(jwtVP, nonce string, requireNonce bool) ([]string, error) {
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

	if requireNonce {
		if attestationVP.CustomFields["nonce"] != nonce {
			return nil, fmt.Errorf("invalid nonce")
		}
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

func removeDuplicates(items []string) []string {
	var uniqueItems []string

	for _, item := range items {
		_, dup := lo.Find(uniqueItems, func(v string) bool { return v == item })
		if !dup {
			uniqueItems = append(uniqueItems, item)
		}
	}

	return uniqueItems
}
