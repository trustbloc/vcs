/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination attestation_service_mocks_test.go -package attestation_test -source=attestation_service.go -mock_names httpClient=MockHTTPClient,vcStatusVerifier=MockVCStatusVerifier

package attestation

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/verifiable"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vcStatusVerifier interface {
	ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer *verifiable.Issuer) error
}

// Config defines configuration for Service.
type Config struct {
	HTTPClient       httpClient
	DocumentLoader   ld.DocumentLoader
	ProofChecker     verifiable.CombinedProofChecker
	VCStatusVerifier vcStatusVerifier
}

// Service implements attestation functionality for OAuth 2.0 Attestation-Based Client Authentication.
type Service struct {
	httpClient       httpClient
	documentLoader   ld.DocumentLoader
	proofChecker     verifiable.CombinedProofChecker
	vcStatusVerifier vcStatusVerifier
}

// NewService returns a new Service instance.
func NewService(config *Config) *Service {
	return &Service{
		httpClient:       config.HTTPClient,
		documentLoader:   config.DocumentLoader,
		proofChecker:     config.ProofChecker,
		vcStatusVerifier: config.VCStatusVerifier,
	}
}

// ValidateClientAttestationJWT validates Client Attestation JWT.
//
//nolint:revive
func (s *Service) ValidateClientAttestationJWT(ctx context.Context, clientID, clientAttestationJWT string) error {
	// TODO: Validate Client Attestation JWT and check the status of Attestation VC.
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-01#section-4.1.1
	return nil
}

// ValidateClientAttestationPoPJWT validates Client Attestation Proof-of-Possession JWT.
//
//nolint:revive
func (s *Service) ValidateClientAttestationPoPJWT(ctx context.Context, clientID, clientAttestationPoPJWT string) error {
	// TODO: Validate Client Attestation Proof of Possession (PoP) JWT.
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-01#section-4.1.2
	return nil
}

// ValidateClientAttestationVP validates Client Attestation VP in jwt_vp format.
//
//nolint:revive
func (s *Service) ValidateClientAttestationVP(ctx context.Context, clientID, jwtVP string) error {
	vp, err := verifiable.ParsePresentation(
		[]byte(jwtVP),
		verifiable.WithPresProofChecker(s.proofChecker),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("parse attestation vp: %w", err)
	}

	if len(vp.Credentials()) == 0 {
		return fmt.Errorf("missing attestation vc")
	}

	attestationVC := vp.Credentials()[0]

	// validate attestation vc
	opts := []verifiable.CredentialOpt{
		verifiable.WithProofChecker(s.proofChecker),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	}

	if err = attestationVC.ValidateCredential(opts...); err != nil {
		return fmt.Errorf("validate attestation vc: %w", err)
	}

	if err = attestationVC.CheckProof(opts...); err != nil {
		return fmt.Errorf("check attestation vc proof: %w", err)
	}

	vcc := attestationVC.Contents()
	if vcc.Expired != nil && time.Now().UTC().After(vcc.Expired.Time) {
		return fmt.Errorf("attestation vc is expired")
	}

	// check attestation vc status
	if err = s.vcStatusVerifier.ValidateVCStatus(ctx, vcc.Status, vcc.Issuer); err != nil {
		return fmt.Errorf("validate attestation vc status: %w", err)
	}

	// TODO: validate attestation vc in trust registry

	return nil
}
