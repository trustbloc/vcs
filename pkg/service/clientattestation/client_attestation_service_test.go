/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/clientattestation"
)

const (
	attestationDID   = "did:example:attestation-service"
	attestationKeyID = "did:example:attestation-service#attestation-key-id"

	walletDID   = "did:example:wallet"
	walletKeyID = "did:example:wallet#wallet-key-id"

	issuerDID   = "did:example:issuer"
	verifierDID = "did:example:verifier"

	issuancePolicyURL     = "https://trust-registry.dev/issuer/policies/{policyID}/{policyVersion}/interactions/issuance"
	presentationPolicyURL = "https://trust-registry.dev/verifier/policies/{policyID}/{policyVersion}/interactions/presentation" //nolint:lll
)

func TestService_ValidateIssuance(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))
	vcStatusVerifier := NewMockVCStatusVerifier(gomock.NewController(t))

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

	var (
		jwtVP   string
		profile *profileapi.Issuer
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"allowed":true}`)),
						}, nil
					},
				)

				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)
				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "fail to parse attestation vp",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				jwtVP = "invalid-jwt-vp"
				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "parse attestation vp")
			},
		},
		{
			name: "no attestation vc found",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				jwtVP = createAttestationVP(t, nil, walletProofCreator)
				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "no attestation vc found")
			},
		},
		{
			name: "attestation vc is expired",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "attestation vc is expired")
			},
		},
		{
			name: "attestation vc subject does not match vp signer",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, "invalid-subject", false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "check attestation vp proof")
			},
		},
		{
			name: "fail to validate attestation vc status",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("validate status error"))

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "validate attestation vc status")
			},
		},
		{
			name: "policy url not set in profile",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = &profileapi.Issuer{
					SigningDID: &profileapi.SigningDID{
						DID: issuerDID,
					},
				}
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "fail to send request to policy evaluation service",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return nil, errors.New("send request error")
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "send request")
			},
		},
		{
			name: "fail to request policy evaluation",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(bytes.NewBufferString("")),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "unexpected status code")
			},
		},
		{
			name: "fail to decode response from policy evaluation service",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString("invalid-response")),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "decode response")
			},
		},
		{
			name: "policy evaluation service returns not allowed",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"allowed":false}`)),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createIssuerProfile(t)
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
						HTTPClient:       httpClient,
						DocumentLoader:   testutil.DocumentLoader(t),
						ProofChecker:     proofChecker,
						VCStatusVerifier: vcStatusVerifier,
					},
				).ValidateIssuance(context.Background(), profile, jwtVP),
			)
		})
	}
}

func TestService_ValidatePresentation(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))
	vcStatusVerifier := NewMockVCStatusVerifier(gomock.NewController(t))

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

	var (
		jwtVP   string
		profile *profileapi.Verifier
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"allowed":true}`)),
						}, nil
					},
				)

				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)

				// create VC that is requested by the verifier
				requestedVC := createVC(
					t,
					"",
					walletDID,
					issuerDID,
					false,
				)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator, requestedVC)
				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "fail to parse attestation vp",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				jwtVP = "invalid-jwt-vp"
				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "parse attestation vp")
			},
		},
		{
			name: "no attestation vc found",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				jwtVP = createAttestationVP(t, nil, walletProofCreator)
				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "no attestation vc found")
			},
		},
		{
			name: "attestation vc is expired",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "attestation vc is expired")
			},
		},
		{
			name: "attestation vc subject does not match vp signer",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, "invalid-subject", false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "check attestation vp proof")
			},
		},
		{
			name: "fail to validate attestation vc status",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("validate status error"))

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "validate attestation vc status")
			},
		},
		{
			name: "policy url not set in profile",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = &profileapi.Verifier{
					SigningDID: &profileapi.SigningDID{
						DID: issuerDID,
					},
				}
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "fail to request policy evaluation",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(bytes.NewBufferString("")),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "unexpected status code")
			},
		},
		{
			name: "policy evaluation service returns not allowed",
			setup: func() {
				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"allowed":false}`)),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				profile = createVerifierProfile(t)
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
						HTTPClient:       httpClient,
						DocumentLoader:   testutil.DocumentLoader(t),
						ProofChecker:     proofChecker,
						VCStatusVerifier: vcStatusVerifier,
					},
				).ValidatePresentation(context.Background(), profile, jwtVP),
			)
		})
	}
}

func createAttestationVC(
	t *testing.T,
	proofCreator jwt.ProofCreator,
	subjectID string,
	expired bool,
) *verifiable.Credential {
	t.Helper()

	vc := createVC(
		t,
		clientattestation.WalletAttestationVCType,
		subjectID,
		attestationDID,
		expired,
	)

	jwtVC, err := vc.CreateSignedJWTVC(false, verifiable.ECDSASecp256r1, proofCreator, attestationKeyID)
	require.NoError(t, err)

	return jwtVC
}

func createVC(
	t *testing.T,
	credentialType string,
	subjectID string,
	issuerID string,
	expired bool,
) *verifiable.Credential {
	t.Helper()

	vcc := verifiable.CredentialContents{
		Context: []string{
			verifiable.ContextURI,
			"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		},
		ID: uuid.New().String(),
		Types: []string{
			verifiable.VCType,
		},
		Subject: []verifiable.Subject{
			{
				ID: subjectID,
			},
		},
		Issuer: &verifiable.Issuer{
			ID: issuerID,
		},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Expired: &utiltime.TimeWrapper{
			Time: time.Now().Add(time.Hour),
		},
	}

	if credentialType != "" {
		vcc.Types = append(vcc.Types, credentialType)
	}

	if expired {
		vcc.Expired = &utiltime.TimeWrapper{
			Time: time.Now().Add(-time.Hour),
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

func createIssuerProfile(t *testing.T) *profileapi.Issuer {
	t.Helper()

	profile := &profileapi.Issuer{
		SigningDID: &profileapi.SigningDID{
			DID: issuerDID,
		},
		Policy: profileapi.Policy{
			URL: issuancePolicyURL,
		},
	}

	return profile
}

func createVerifierProfile(t *testing.T) *profileapi.Verifier {
	t.Helper()

	profile := &profileapi.Verifier{
		SigningDID: &profileapi.SigningDID{
			DID: verifierDID,
		},
		Policy: profileapi.Policy{
			URL: presentationPolicyURL,
		},
	}

	return profile
}
