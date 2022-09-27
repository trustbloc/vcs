/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifycredential

import (
	_ "embed"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	vcformats "github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/verifier"
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string

	// nolint:gochecknoglobals
	verificationChecks = &verifier.VerificationChecks{
		Credential: verifier.CredentialChecks{
			Proof: true,
			Format: []vcformats.Format{
				vcformats.Jwt,
				vcformats.Ldp,
			},
			Status: true,
		},
	}

	// nolint:gochecknoglobals
	testProfile = &verifier.Profile{
		ID:             "id",
		Name:           "test profile",
		URL:            "https://test-verifier.com",
		Active:         true,
		OrganizationID: "orgID",
		Checks:         verificationChecks,
	}
)

func TestService_VerifyCredential(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		loader := testutil.DocumentLoader(t)
		mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
		mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
			Subject: []verifiable.Subject{{
				ID: "",
				CustomFields: map[string]interface{}{
					"statusListIndex": "1",
					"statusPurpose":   "2",
					"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
				},
			}},
			Issuer: verifiable.Issuer{
				ID: "did:trustblock:abc",
			},
		}, nil)

		tests := []struct {
			name string
			kt   kmskeytypes.KeyType
		}{
			{
				name: "Algorithm ED25519",
				kt:   kmskeytypes.ED25519Type,
			},
			{
				name: "Algorithm ECDSA P256",
				kt:   kmskeytypes.ECDSAP256TypeIEEEP1363,
			},
			{
				name: "Algorithm ECDSA P384",
				kt:   kmskeytypes.ECDSAP384TypeIEEEP1363,
			},
			{
				name: "Algorithm ECDSA P521",
				kt:   kmskeytypes.ECDSAP521TypeIEEEP1363,
			},
		}
		for _, ktTestCase := range tests {
			t.Run(ktTestCase.name, func(t *testing.T) {
				tests := []struct {
					name string
					sr   verifiable.SignatureRepresentation
				}{
					{
						name: "Signature representation JWS",
						sr:   verifiable.SignatureJWS,
					},
					{
						name: "Signature representation ProofValue",
						sr:   verifiable.SignatureProofValue,
					},
				}
				for _, sigRepresentationTextCase := range tests {
					t.Run(sigRepresentationTextCase.name, func(t *testing.T) {
						tests := []struct {
							name   string
							vcFile []byte
						}{
							{
								name:   "Credential format JWT",
								vcFile: []byte(sampleVCJWT),
							},
							{
								name:   "Credential format JSON-LD",
								vcFile: []byte(sampleVCJsonLD),
							},
						}
						for _, vcFileTestCase := range tests {
							t.Run(vcFileTestCase.name, func(t *testing.T) {
								// Assert
								vc, vdr := testutil.SignedVC(
									t, vcFileTestCase.vcFile, ktTestCase.kt, sigRepresentationTextCase.sr,
									loader, crypto.AssertionMethod)

								// Verify
								op := New(&Config{
									VcStatusManager: mockVCStatusManager,
									VDR:             vdr,
									DocumentLoader:  loader,
								})

								res, err := op.VerifyCredential(vc, &Options{
									Challenge: crypto.Challenge,
									Domain:    crypto.Domain,
								}, testProfile)

								require.NoError(t, err)
								require.Nil(t, res)
							})
						}
					})
				}
			})
		}
	})

	t.Run("Failed", func(t *testing.T) {
		// Assert
		mockVDRRegistry := &vdrmock.MockVDRegistry{}
		loader := testutil.DocumentLoader(t)

		vc, err := verifiable.ParseCredential(
			[]byte(sampleVCJsonLD),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		t.Run("Proof", func(t *testing.T) {
			mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
			mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
				Subject: []verifiable.Subject{{
					ID: "",
					CustomFields: map[string]interface{}{
						"statusListIndex": "1",
						"statusPurpose":   "2",
						"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
					},
				}},
				Issuer: verifiable.Issuer{
					ID: "did:trustblock:abc",
				},
			}, nil)
			service := New(&Config{
				VcStatusManager: mockVCStatusManager,
				VDR:             mockVDRRegistry,
				DocumentLoader:  loader,
			})

			var res []CredentialsVerificationCheckResult

			res, err = service.VerifyCredential(vc, &Options{
				Challenge: crypto.Challenge,
				Domain:    crypto.Domain,
			}, testProfile)

			require.NoError(t, err)
			require.Len(t, res, 1)
		})

		t.Run("Proof and Status", func(t *testing.T) {
			require.NoError(t, err)
			failedMockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
			failedMockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
				Subject: []verifiable.Subject{{
					ID: "",
					CustomFields: map[string]interface{}{
						"statusListIndex": "1",
						"statusPurpose":   "2",
						"encodedList":     "H4sIAAAAAAAA_2ICBAAA__-hjgw8AQAAAA",
					},
				}},
				Issuer: verifiable.Issuer{
					ID: "did:trustblock:abc",
				},
			}, nil)
			service := New(&Config{
				VcStatusManager: failedMockVCStatusManager,
				VDR:             mockVDRRegistry,
				DocumentLoader:  loader,
			})
			res, err := service.VerifyCredential(vc, &Options{
				Challenge: crypto.Challenge,
				Domain:    crypto.Domain,
			}, testProfile)

			require.NoError(t, err)
			require.Len(t, res, 2)
		})
	})
}

func TestService_checkVCStatus(t *testing.T) {
	validVCStatus := &verifiable.TypedID{
		ID:   "https://issuer-vcs.sandbox.trustbloc.dev/vc-issuer-test-2/status/1#0",
		Type: "StatusList2021Entry",
		CustomFields: map[string]interface{}{
			"statusListIndex":      "1",
			"statusListCredential": "",
			"statusPurpose":        "2",
		},
	}

	type fields struct {
		getVCStatusManager func() vcStatusManager
	}
	type args struct {
		getVcStatus func() *verifiable.TypedID
		issuer      string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
						Subject: []verifiable.Subject{{
							ID: "",
							CustomFields: map[string]interface{}{
								"statusListIndex": "1",
								"statusPurpose":   "2",
								"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
							},
						}},
						Issuer: verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}, nil)

					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return validVCStatus
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: false,
		},
		{
			name: "ValidateVCStatus error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					return nil
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return nil
				},
			},
			wantErr: true,
		},
		{
			name: "statusListIndex invalid value error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					return nil
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return &verifiable.TypedID{
						ID:   "https://issuer-vcs.sandbox.trustbloc.dev/vc-issuer-test-2/status/1#0",
						Type: "StatusList2021Entry",
						CustomFields: map[string]interface{}{
							"statusListIndex":      "abc",
							"statusListCredential": "",
							"statusPurpose":        "2",
						},
					}
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "GetRevocationListVC error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(
						nil, errors.New("some error"))
					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return validVCStatus
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "revocationListVC invalid issuer error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
						Subject: []verifiable.Subject{},
						Issuer: verifiable.Issuer{
							ID: "did:trustblock:123",
						},
					}, nil)

					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return validVCStatus
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "revocationListVC invalid subject field error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
						Subject: verifiable.Subject{},
						Issuer: verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}, nil)

					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return validVCStatus
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "revocationListVC invalid StatusPurpose field error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
						Subject: []verifiable.Subject{{
							ID: "",
							CustomFields: map[string]interface{}{
								"statusListIndex": "1",
								"statusPurpose":   "abc",
								"encodedList":     "",
							},
						}},
						Issuer: verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}, nil)

					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return validVCStatus
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "revocationListVC invalid encodedList field error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
						Subject: []verifiable.Subject{{
							ID: "",
							CustomFields: map[string]interface{}{
								"statusListIndex": "1",
								"statusPurpose":   "2",
								"encodedList":     "",
							},
						}},
						Issuer: verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}, nil)

					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return validVCStatus
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "revocationListVC bitString.Get() error",
			fields: fields{
				getVCStatusManager: func() vcStatusManager {
					mockVCStatusManager := NewMockVcStatusManager(gomock.NewController(t))
					mockVCStatusManager.EXPECT().GetRevocationListVC(gomock.Any()).AnyTimes().Return(&verifiable.Credential{
						Subject: []verifiable.Subject{{
							ID: "",
							CustomFields: map[string]interface{}{
								"statusListIndex": "1",
								"statusPurpose":   "2",
								"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
							},
						}},
						Issuer: verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}, nil)

					return mockVCStatusManager
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return &verifiable.TypedID{
						ID:   "https://issuer-vcs.sandbox.trustbloc.dev/vc-issuer-test-2/status/1#0",
						Type: "StatusList2021Entry",
						CustomFields: map[string]interface{}{
							"statusListIndex":      "-1",
							"statusListCredential": "",
							"statusPurpose":        "2",
						},
					}
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vcStatusManager: tt.fields.getVCStatusManager(),
			}
			err := s.ValidateVCStatus(tt.args.getVcStatus(), tt.args.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateVCStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestService_validateVCStatus(t *testing.T) {
	type args struct {
		vcStatus *verifiable.TypedID
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "",
						"statusPurpose":        "2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Error not exist",
			args: args{
				vcStatus: nil,
			},
			wantErr: true,
		},
		{
			name: "Error status not supported",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "statusPurpose",
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusListIndex empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListCredential": "",
						"statusPurpose":        "2",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusListCredential empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListIndex": "1",
						"statusPurpose":   "2",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error statusPurpose empty",
			args: args{
				vcStatus: &verifiable.TypedID{
					Type: "StatusList2021Entry",
					CustomFields: map[string]interface{}{
						"statusListIndex":      "1",
						"statusListCredential": "",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{}
			if err := s.validateVCStatus(tt.args.vcStatus); (err != nil) != tt.wantErr {
				t.Errorf("validateVCStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_ValidateCredentialProof(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	signedVC, vdr := testutil.SignedVC(
		t, []byte(sampleVCJsonLD), kmskeytypes.ED25519Type, verifiable.SignatureProofValue, loader, crypto.AssertionMethod)
	type args struct {
		getVcByte        func() []byte
		proofChallenge   string
		proofDomain      string
		vcInVPValidation bool
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ProofChallenge invalid value",
			args: args{
				getVcByte: func() []byte {
					vc := *signedVC
					b, _ := vc.MarshalJSON()
					return b
				},
				proofChallenge:   "some value",
				vcInVPValidation: false,
			},
			wantErr: true,
		},
		{
			name: "ProofDomain invalid value",
			args: args{
				getVcByte: func() []byte {
					vc := *signedVC
					b, _ := vc.MarshalJSON()
					return b
				},
				proofChallenge:   crypto.Challenge,
				proofDomain:      "some value",
				vcInVPValidation: false,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				documentLoader: loader,
				vdr:            vdr,
			}
			if err := s.ValidateCredentialProof(
				tt.args.getVcByte(),
				tt.args.proofChallenge,
				tt.args.proofDomain,
				tt.args.vcInVPValidation); (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentialProof() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
