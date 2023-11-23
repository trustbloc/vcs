/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_attestation_service_mocks_test.go -package clientattestation_test -source=client_attestation_service.go -mock_names httpClient=MockHTTPClient,vcStatusVerifier=MockVCStatusVerifier

package clientattestation

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
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

// ValidateAttestationJWTVP validates attestation VP in jwt_vp format.
//
//nolint:revive
func (s *Service) ValidateAttestationJWTVP(ctx context.Context, profile *profileapi.Issuer, jwtVP string) error {
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

	vc := vp.Credentials()[0]

	// validate attestation VC
	opts := []verifiable.CredentialOpt{
		verifiable.WithProofChecker(s.proofChecker),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	}

	if err = vc.ValidateCredential(opts...); err != nil {
		return fmt.Errorf("validate attestation vc: %w", err)
	}

	if err = vc.CheckProof(opts...); err != nil {
		return fmt.Errorf("check attestation vc proof: %w", err)
	}

	vcc := vc.Contents()
	if vcc.Expired != nil && time.Now().UTC().After(vcc.Expired.Time) {
		return fmt.Errorf("attestation vc is expired")
	}

	if len(vcc.Subject) == 0 || vcc.Subject[0].ID != vp.Holder {
		return fmt.Errorf("attestation vc subject does not match vp holder")
	}

	// check attestation VC status
	if err = s.vcStatusVerifier.ValidateVCStatus(ctx, vcc.Status, vcc.Issuer); err != nil {
		return fmt.Errorf("validate attestation vc status: %w", err)
	}

	// TODO: validate attestation vc in trust registry

	return nil
}
