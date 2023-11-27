/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation_test

import (
	"context"
	"errors"
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
)

func TestService_ValidateClientAttestationJWTVP(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))
	vcStatusVerifier := NewMockVCStatusVerifier(gomock.NewController(t))

	var jwtVP string
	var profile *profileapi.Issuer

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
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success",
			setup: func() {
				// create wallet attestation VC with wallet DID as subject and attestation DID as issuer
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)

				// prepare wallet attestation VP (in jwt_vp format) signed by wallet DID
				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
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
			name: "missing attestation vc",
			setup: func() {
				jwtVP = createAttestationVP(t, nil, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing attestation vc")
			},
		},
		{
			name: "attestation vc is expired",
			setup: func() {
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, true)

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
				attestationVC := createAttestationVC(t, attestationProofCreator, "invalid-subject", false)

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
				attestationVC := createAttestationVC(t, attestationProofCreator, walletDID, false)

				jwtVP = createAttestationVP(t, attestationVC, walletProofCreator)

				proofChecker = defaultProofChecker

				vcStatusVerifier.EXPECT().ValidateVCStatus(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("validate status error"))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "validate attestation vc status")
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
				).ValidateAttestationJWTVP(context.Background(), profile, jwtVP),
			)
		})
	}
}

func createAttestationVC(
	t *testing.T,
	proofCreator jwt.ProofCreator,
	subject string,
	isExpired bool,
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
			clientattestation.WalletAttestationVCType,
		},
		Subject: []verifiable.Subject{
			{
				ID: subject,
			},
		},
		Issuer: &verifiable.Issuer{
			ID: attestationDID,
		},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
	}

	if isExpired {
		vcc.Expired = &utiltime.TimeWrapper{
			Time: time.Now().Add(-1 * time.Hour),
		}
	}

	vc, err := verifiable.CreateCredential(vcc, nil)
	require.NoError(t, err)

	jwtVC, err := vc.CreateSignedJWTVC(
		false,
		verifiable.ECDSASecp256r1,
		proofCreator,
		attestationKeyID,
	)
	require.NoError(t, err)

	return jwtVC
}

func createAttestationVP(
	t *testing.T,
	attestationVC *verifiable.Credential,
	proofCreator jwt.ProofCreator,
) string {
	t.Helper()

	vp, err := verifiable.NewPresentation()
	require.NoError(t, err)

	if attestationVC != nil {
		vp.AddCredentials(attestationVC)
	}

	vp.ID = uuid.New().String()

	claims, err := vp.JWTClaims([]string{}, false)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ECDSAP256TypeDER)
	require.NoError(t, err)

	jws, err := claims.MarshalJWS(jwsAlgo, proofCreator, walletKeyID)
	require.NoError(t, err)

	return jws
}
