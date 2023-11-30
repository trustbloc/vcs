/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_attestation_service_mocks_test.go -package clientattestation_test -source=client_attestation_service.go -mock_names httpClient=MockHTTPClient,vcStatusVerifier=MockVCStatusVerifier

package clientattestation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type vcStatusVerifier interface {
	ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer *verifiable.Issuer) error
}

type TrustRegistryPayloadBuilder func(
	clientDID string, attestationVC *verifiable.Credential, vp *verifiable.Presentation) ([]byte, error)

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
// Arguments:
//
//	jwtVP 	  		- presentation contains attestation VC
//	policyURL 		- Trust Registry policy URL
//	clientDID  		- DID identifier.
//
// payloadBuilder 	- payload builder function.
//
//nolint:revive
func (s *Service) ValidateAttestationJWTVP(
	ctx context.Context,
	jwtVP string,
	policyURL string,
	clientDID string,
	payloadBuilder TrustRegistryPayloadBuilder,
) error {
	vp, err := verifiable.ParsePresentation(
		[]byte(jwtVP),
		// The verification of proof is conducted manually, along with an extra verification to ensure that signer of
		// the VP matches the subject of the attestation VC.
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(s.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("parse attestation vp: %w", err)
	}

	attestationVC, found := lo.Find(vp.Credentials(), func(item *verifiable.Credential) bool {
		return lo.Contains(item.Contents().Types, walletAttestationVCType)
	})

	if !found {
		return errors.New("attestation vc is not supplied")
	}

	// validate attestation VC
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

	// validate vp proof with extra check for wallet binding
	if err = jwt.CheckProof(jwtVP, s.proofChecker, &vcc.Subject[0].ID, nil); err != nil {
		return fmt.Errorf("check attestation vp proof: %w", err)
	}

	// check attestation VC status
	if err = s.vcStatusVerifier.ValidateVCStatus(ctx, vcc.Status, vcc.Issuer); err != nil {
		return fmt.Errorf("validate attestation vc status: %w", err)
	}

	var trustRegistryRequestBody []byte
	trustRegistryRequestBody, err = payloadBuilder(clientDID, attestationVC, vp)
	if err != nil {
		return fmt.Errorf("payload builder: %w", err)
	}

	responseDecoded, err := s.doTrustRegistryRequest(ctx, policyURL, trustRegistryRequestBody)
	if err != nil {
		return err
	}

	if !responseDecoded.Allowed {
		return ErrInteractionRestricted
	}

	return nil
}
