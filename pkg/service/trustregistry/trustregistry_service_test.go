/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:gocritic
package trustregistry_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/trustbloc/vcs/pkg/service/trustregistry"
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

	testNonce = "nonce"
)

func TestService_ValidateIssuance(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))

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
		attestationVP   string
		nonce           string
		credentialTypes []string
		profile         *profileapi.Issuer
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

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						payload := &trustregistry.IssuancePolicyEvaluationRequest{}

						require.NoError(t, json.NewDecoder(req.Body).Decode(payload))
						require.Equal(t, []string{"Credential1", "Credential2"}, payload.CredentialTypes)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"allowed":true}`)),
						}, nil
					},
				)

				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce
				credentialTypes = []string{"Credential1", "Credential2", "Credential1"}
				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "fail to parse jwt vp",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVP = "invalid-jwt-vp"
				nonce = testNonce
				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "parse jwt")
			},
		},
		{
			name: "invalid attestation vp audience",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "some issuer", testNonce)
				nonce = testNonce

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid audience")
			},
		},
		{
			name: "invalid nonce",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, "invalid nonce")
				nonce = testNonce

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid nonce")
			},
		},
		{
			name: "attestation vc is expired",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

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

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, "invalid-subject", false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "check attestation vp proof")
			},
		},
		{
			name: "policy url not set in profile",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

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

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return nil, errors.New("send request error")
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

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

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(bytes.NewBufferString("")),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "status code")
			},
		},
		{
			name: "fail to decode response from policy evaluation service",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString("invalid-response")),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

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

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body: io.NopCloser(
								bytes.NewBufferString(`{"allowed":false,"deny_reasons":["issuer is not authorized"]}`),
							),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, issuerDID, testNonce)
				nonce = testNonce

				profile = createIssuerProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, trustregistry.ErrInteractionRestricted)
				require.ErrorContains(t, err, "issuer is not authorized")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			tt.check(t,
				trustregistry.NewService(
					&trustregistry.Config{
						HTTPClient:     httpClient,
						DocumentLoader: testutil.DocumentLoader(t),
						ProofChecker:   proofChecker,
					},
				).ValidateIssuance(
					context.Background(),
					profile,
					&trustregistry.ValidateIssuanceData{
						AttestationVP:   attestationVP,
						Nonce:           nonce,
						CredentialTypes: credentialTypes,
					},
				),
			)
		})
	}
}

func TestService_ValidatePresentation(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))

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
		attestationVP string
		profile       *profileapi.Verifier
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
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "", "", requestedVC)
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

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVP = "invalid-jwt-vp"
				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "parse attestation vp")
			},
		},
		{
			name: "attestation vc is expired",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "", "")

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

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, "invalid-subject", false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "", "")

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "check attestation vp proof")
			},
		},
		{
			name: "policy url not set in profile",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "", "")

				profile = &profileapi.Verifier{
					SigningDID: &profileapi.SigningDID{
						DID: issuerDID,
					},
					Checks: &profileapi.VerificationChecks{},
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

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(bytes.NewBufferString("")),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "", "")

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "status code")
			},
		},
		{
			name: "policy evaluation service returns not allowed",
			setup: func() {
				proofChecker = defaultProofChecker

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"allowed":false}`)),
						}, nil
					},
				)

				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)
				attestationVP = createAttestationVP(t, attestationVC, walletProofCreator, "", "")

				profile = createVerifierProfile(t)
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, trustregistry.ErrInteractionRestricted)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			tt.check(t,
				trustregistry.NewService(
					&trustregistry.Config{
						HTTPClient:     httpClient,
						DocumentLoader: testutil.DocumentLoader(t),
						ProofChecker:   proofChecker,
					},
				).ValidatePresentation(
					context.Background(),
					profile,
					&trustregistry.ValidatePresentationData{
						AttestationVP:     attestationVP,
						CredentialMatches: nil,
					},
				),
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
		trustregistry.WalletAttestationVCType,
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
	audience string,
	nonce string,
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

	if nonce != "" {
		vp.CustomFields = map[string]interface{}{
			"nonce": nonce,
		}
	}

	var aud []string

	if audience != "" {
		aud = []string{audience}
	}

	claims, err := vp.JWTClaims(aud, false)
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
		Checks: profileapi.IssuanceChecks{
			Policy: profileapi.PolicyCheck{
				PolicyURL: issuancePolicyURL,
			},
		},
		CredentialTemplates: []*profileapi.CredentialTemplate{
			{
				Type: "VerifiedDocument",
			},
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
		Checks: &profileapi.VerificationChecks{
			Policy: profileapi.PolicyCheck{
				PolicyURL: presentationPolicyURL,
			},
		},
	}

	return profile
}
