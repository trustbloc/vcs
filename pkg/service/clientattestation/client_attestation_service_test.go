/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/service/clientattestation"
)

const (
	attestationDID   = "did:example:attestation-service"
	attestationKeyID = "did:example:attestation-service#attestation-key-id"

	walletDID   = "did:example:wallet"
	verifierDID = "did:example:verifier"
	walletKeyID = "did:example:wallet#wallet-key-id"
)

func TestService_ValidateClientAttestationJWTVP(t *testing.T) {
	now := time.Now().UTC()
	handler := echo.New()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	vcStatusVerifier := NewMockVCStatusVerifier(gomock.NewController(t))

	var jwtVP string
	var clientDID string
	var payloadBuilder clientattestation.TrustRegistryPayloadBuilder

	proofCreators, defaultProofChecker := testsupport.NewKMSSignersAndVerifier(t,
		[]testsupport.SigningKey{
			{
				Type:        kms.ECDSAP256TypeDER,
				PublicKeyID: attestationKeyID,
			},
			{
				Type:        kms.ECDSAP256TypeDER,
				PublicKeyID: walletKeyID,
			},
		},
	)

	attestationProofCreator := proofCreators[0]
	walletProofCreator := proofCreators[1]

	var proofChecker *checker.ProofChecker

	tests := []struct {
		name  string
		url   string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success OIDC4CI",
			url:  srv.URL + "/success_oidc4ci",
			setup: func() {
				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				payloadBuilder = clientattestation.IssuerInteractionTrustRegistryPayloadBuilder

				handler.Add(http.MethodPost, "/success_oidc4ci", func(c echo.Context) error {
					var got *clientattestation.IssuerInteractionValidationConfig
					assert.NoError(t, c.Bind(&got))

					attestationVCUniversalForm, err := attestationVC.ToUniversalForm()
					assert.NoError(t, err)

					expected := &clientattestation.IssuerInteractionValidationConfig{
						AttestationVC: attestationVCUniversalForm,
						Metadata: []*clientattestation.CredentialMetadata{
							getAttestationVCMetadata(t, now, false),
						},
					}

					assert.Equal(t, expected, got)

					return c.JSON(http.StatusOK, map[string]bool{"allowed": true})
				})
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "success OIDC4VP",
			url:  srv.URL + "/success_oidc4vp",
			setup: func() {
				clientDID = verifierDID

				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, false)

				// create dummy requested credential
				requestedVC := createRequestedVC(t, now)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator, requestedVC)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				payloadBuilder = clientattestation.VerifierInteractionTrustRegistryPayloadBuilder

				handler.Add(http.MethodPost, "/success_oidc4vp", func(c echo.Context) error {
					var got *clientattestation.VerifierPresentationValidationConfig
					assert.NoError(t, c.Bind(&got))

					attestationVCJWT, err := attestationVC.ToJWTString()
					assert.NoError(t, err)

					expected := &clientattestation.VerifierPresentationValidationConfig{
						AttestationVC: []string{attestationVCJWT},
						VerifierDID:   verifierDID,
						RequestedVCMetadata: []*clientattestation.CredentialMetadata{
							getAttestationVCMetadata(t, now, false),
							getRequestedVCMetadata(t, now),
						},
					}

					assert.Equal(t, expected, got)

					return c.JSON(http.StatusOK, map[string]bool{"allowed": true})
				})
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "fail to parse attestation vp",
			setup: func() {
				jwtVP = "invalid-jwt-vp"

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "parse attestation vp")
			},
		},
		{
			name: "attestation vc is not supplied",
			setup: func() {
				jwtVP = createAttestationVP(t, nil, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "attestation vc is not supplied")
			},
		},
		{
			name: "attestation vc is expired",
			setup: func() {
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, true)

				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "attestation vc is expired")
			},
		},
		{
			name: "attestation vc subject does not match vp signer",
			setup: func() {
				attestationVC := createAttestationVC(t, attestationProofCreator, "invalid-subject", now, false)

				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "check attestation vp proof")
			},
		},
		{
			name: "fail to check attestation vc status",
			setup: func() {
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, false)

				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("validate status error"))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "validate attestation vc status")
			},
		},
		{
			name: "error payload builder",
			setup: func() {
				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				payloadBuilder = func(_ string, _ *verifiable.Credential, _ *verifiable.Presentation) ([]byte, error) {
					return nil, errors.New("some error")
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "payload builder:")
			},
		},
		{
			name: "error doTrustRegistryRequest",
			url:  srv.URL + "/testcase2",
			setup: func() {
				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				payloadBuilder = clientattestation.VerifierInteractionTrustRegistryPayloadBuilder

				handler.Add(http.MethodPost, "/testcase2", func(c echo.Context) error {
					return c.NoContent(http.StatusBadRequest)
				})
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "unexpected status code")
			},
		},
		{
			name: "Error interaction restricted",
			url:  srv.URL + "/testcase3",
			setup: func() {
				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, now, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				payloadBuilder = clientattestation.VerifierInteractionTrustRegistryPayloadBuilder

				handler.Add(http.MethodPost, "/testcase3", func(c echo.Context) error {
					return c.JSON(http.StatusOK, map[string]bool{"allowed": false})
				})
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, clientattestation.ErrInteractionRestricted)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			tt.check(t,
				clientattestation.NewService(
					&clientattestation.Config{
						HTTPClient:       http.DefaultClient,
						DocumentLoader:   testutil.DocumentLoader(t),
						ProofChecker:     proofChecker,
						VCStatusVerifier: vcStatusVerifier,
					},
				).ValidateAttestationJWTVP(context.Background(), jwtVP, tt.url, clientDID, payloadBuilder),
			)
		})
	}
}

func createAttestationVC(
	t *testing.T,
	proofCreator jwt.ProofCreator,
	subject string,
	now time.Time,
	isExpired bool,
) *verifiable.Credential {
	t.Helper()

	vcType := []string{verifiable.VCType, "WalletAttestationCredential"}

	vc := createVC(t, "attestationVCCredentialID", vcType, subject, attestationDID, now, isExpired)

	jwtVC, err := vc.CreateSignedJWTVC(
		false,
		verifiable.ECDSASecp256r1,
		proofCreator,
		attestationKeyID,
	)
	require.NoError(t, err)

	return jwtVC
}

func createRequestedVC(
	t *testing.T,
	now time.Time,
) *verifiable.Credential {
	t.Helper()

	id := "requestedVCCredentialID"
	types := []string{verifiable.VCType}

	return createVC(t, id, types, uuid.NewString(), walletDID, now.Round(time.Second), true)
}

func createVC(
	t *testing.T,
	credentialID string,
	types []string,
	subjectID string,
	issuerDID string,
	now time.Time,
	isExpired bool,
) *verifiable.Credential {
	t.Helper()

	vcc := verifiable.CredentialContents{
		Context: []string{
			verifiable.ContextURI,
			"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		},
		ID:    credentialID,
		Types: types,
		Subject: []verifiable.Subject{
			{
				ID: subjectID,
			},
		},
		Issuer: &verifiable.Issuer{
			ID: issuerDID,
		},
		Issued: &utiltime.TimeWrapper{
			Time: now,
		},
	}

	if isExpired {
		vcc.Expired = &utiltime.TimeWrapper{
			Time: now.Add(-time.Hour),
		}
	}

	vc, err := verifiable.CreateCredential(vcc, nil)
	require.NoError(t, err)

	return vc
}

func createAttestationVP(
	t *testing.T,
	attestationVC *verifiable.Credential,
	proofCreator jwt.ProofCreator,
	requestedVCs ...*verifiable.Credential,
) string {
	t.Helper()

	vp, err := verifiable.NewPresentation()
	require.NoError(t, err)

	if attestationVC != nil {
		vp.AddCredentials(attestationVC)
	}

	vp.AddCredentials(requestedVCs...)

	vp.ID = uuid.New().String()

	claims, err := vp.JWTClaims([]string{}, false)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ECDSAP256TypeDER)
	require.NoError(t, err)

	jws, err := claims.MarshalJWS(jwsAlgo, proofCreator, walletKeyID)
	require.NoError(t, err)

	return jws
}

func getAttestationVCMetadata(t *testing.T, now time.Time, expired bool) *clientattestation.CredentialMetadata {
	t.Helper()

	var exp string
	if expired {
		exp = now.Add(-time.Hour).Format(time.RFC3339)
	}

	return &clientattestation.CredentialMetadata{
		CredentialID: "attestationVCCredentialID",
		Types: []string{
			"VerifiableCredential",
			"WalletAttestationCredential",
		},
		IssuerID: attestationDID,
		Issued:   now.Format(time.RFC3339),
		Expired:  exp,
	}
}

func getRequestedVCMetadata(t *testing.T, now time.Time) *clientattestation.CredentialMetadata {
	t.Helper()

	return &clientattestation.CredentialMetadata{
		CredentialID: "requestedVCCredentialID",
		Types: []string{
			"VerifiableCredential",
		},
		IssuerID: walletDID,
		Issued:   now.Round(time.Second).Format(time.RFC3339),
		Expired:  now.Round(time.Second).Add(-time.Hour).Format(time.RFC3339),
	}
}
