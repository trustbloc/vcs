/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifycredential

import (
	"context"
	_ "embed"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/mock/status"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string

	// nolint:gochecknoglobals
	verificationChecks = &profileapi.VerificationChecks{
		Credential: profileapi.CredentialChecks{
			Proof: true,
			Format: []vcs.Format{
				vcs.Jwt,
				vcs.Ldp,
			},
			Status: true,
		},
	}

	// nolint:gochecknoglobals
	testProfile = &profileapi.Verifier{
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
		mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
		mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
			&verifiable.Credential{
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
				name: "Algorithm ECDSA ES256",
				kt:   kmskeytypes.ECDSAP256TypeIEEEP1363,
			},
			{
				name: "Algorithm ECDSA ES384",
				kt:   kmskeytypes.ECDSAP384TypeIEEEP1363,
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
							name string
							sf   vcs.Format
						}{
							{
								name: "Signature format JWT",
								sf:   vcs.Jwt,
							},
							{
								name: "Signature format LDP",
								sf:   vcs.Ldp,
							},
						}
						for _, signatureFormatTestCase := range tests {
							t.Run(signatureFormatTestCase.name, func(t *testing.T) {
								tests := []struct {
									name    string
									vcFile  []byte
									isSDJWT bool
								}{
									{
										name:   "Credential format JWT",
										vcFile: []byte(sampleVCJWT),
									},
									{
										name:    "Credential format SD-JWT",
										vcFile:  []byte(sampleVCJWT),
										isSDJWT: true,
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
											signatureFormatTestCase.sf,
											loader,
											crypto.AssertionMethod,
											vcFileTestCase.isSDJWT)
										mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
											StatusProcessor: &status.MockVCStatusProcessor{
												StatusListIndex: 1,
											},
										}

										// Verify
										op := New(&Config{
											VCStatusProcessorGetter: mockStatusProcessorGetter.GetMockStatusProcessor,
											StatusListVCResolver:    mockStatusListVCGetter,
											VDR:                     vdr,
											DocumentLoader:          loader,
										})

										res, err := op.VerifyCredential(context.Background(), vc, &Options{
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
		}

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
				mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
				mockStatusListVCGetter.EXPECT().Resolve(
					context.Background(), gomock.Any()).AnyTimes().Return(
					&verifiable.Credential{
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

				mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
					StatusProcessor: &status.MockVCStatusProcessor{
						StatusListIndex: 1,
					},
				}

				service := New(&Config{
					VCStatusProcessorGetter: mockStatusProcessorGetter.GetMockStatusProcessor,
					StatusListVCResolver:    mockStatusListVCGetter,
					VDR:                     mockVDRRegistry,
					DocumentLoader:          loader,
				})

				var res []CredentialsVerificationCheckResult

				res, err = service.VerifyCredential(context.Background(), vc, &Options{
					Challenge: crypto.Challenge,
					Domain:    crypto.Domain,
				}, testProfile)

				require.NoError(t, err)
				require.Len(t, res, 1)
			})

			t.Run("Proof and Status", func(t *testing.T) {
				require.NoError(t, err)
				failedStatusListGetter := NewMockStatusListVCResolver(gomock.NewController(t))
				failedStatusListGetter.EXPECT().Resolve(
					context.Background(), gomock.Any()).AnyTimes().Return(
					&verifiable.Credential{
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

				mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
					StatusProcessor: &status.MockVCStatusProcessor{
						ValidateErr: errors.New("some error"),
					},
				}

				service := New(&Config{
					VCStatusProcessorGetter: mockStatusProcessorGetter.GetMockStatusProcessor,
					StatusListVCResolver:    failedStatusListGetter,
					VDR:                     mockVDRRegistry,
					DocumentLoader:          loader,
				})
				res, err := service.VerifyCredential(context.Background(), vc, &Options{
					Challenge: crypto.Challenge,
					Domain:    crypto.Domain,
				}, testProfile)

				require.NoError(t, err)
				require.Len(t, res, 2)
			})
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
		getStatusListVCGetter      func() statusListVCURIResolver
		getVCStatusProcessorGetter func() vc.StatusProcessorGetter
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
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(),
						"https://example.com/status/1").AnyTimes().Return(&verifiable.Credential{
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

					return mockStatusListVCGetter
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{
							StatusVCURI:     "https://example.com/status/1",
							StatusListIndex: 1,
						},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
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
			name: "VCStatusProcessorGetter error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					return nil
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						Err: errors.New("some error"),
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return &verifiable.TypedID{}
				},
			},
			wantErr: true,
		},
		{
			name: "ValidateVCStatus error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					return nil
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{
							ValidateErr: errors.New("some error"),
						},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return &verifiable.TypedID{}
				},
			},
			wantErr: true,
		},
		{
			name: "statusListIndex invalid value error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					return nil
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{
							GetStatusListIndexErr: errors.New("some error"),
						},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return &verifiable.TypedID{}
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "GetStatusVCURI error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					return nil
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{
							GetStatusVCURIErr: errors.New("some error"),
						},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
				},
			},
			args: args{
				getVcStatus: func() *verifiable.TypedID {
					return &verifiable.TypedID{}
				},
				issuer: "did:trustblock:abc",
			},
			wantErr: true,
		},
		{
			name: "GetStatusListVC error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						nil, errors.New("some error"))
					return mockStatusListVCGetter
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
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
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(
						context.Background(), gomock.Any()).AnyTimes().Return(
						&verifiable.Credential{
							Subject: []verifiable.Subject{},
							Issuer: verifiable.Issuer{
								ID: "did:trustblock:123",
							},
						}, nil)

					return mockStatusListVCGetter
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
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
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						&verifiable.Credential{
							Subject: verifiable.Subject{},
							Issuer: verifiable.Issuer{
								ID: "did:trustblock:abc",
							},
						}, nil)

					return mockStatusListVCGetter
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
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
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						&verifiable.Credential{
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

					return mockStatusListVCGetter
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
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
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						&verifiable.Credential{
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

					return mockStatusListVCGetter
				},
				getVCStatusProcessorGetter: func() vc.StatusProcessorGetter {
					mockStatusProcessorGetter := &status.MockStatusProcessorGetter{
						StatusProcessor: &status.MockVCStatusProcessor{
							StatusListIndex: -1,
						},
					}

					return mockStatusProcessorGetter.GetMockStatusProcessor
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
				vcStatusProcessorGetter: tt.fields.getVCStatusProcessorGetter(),
				statusListVCURIResolver: tt.fields.getStatusListVCGetter(),
			}
			err := s.ValidateVCStatus(context.Background(), tt.args.getVcStatus(), tt.args.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateVCStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestService_ValidateCredentialProof(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	signedVC, vdr := testutil.SignedVC(
		t, []byte(sampleVCJsonLD), kmskeytypes.ED25519Type,
		verifiable.SignatureProofValue, vcs.Ldp, loader, crypto.AssertionMethod, false)
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
				context.Background(),
				tt.args.getVcByte(),
				tt.args.proofChallenge,
				tt.args.proofDomain,
				tt.args.vcInVPValidation,
				true); (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentialProof() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
