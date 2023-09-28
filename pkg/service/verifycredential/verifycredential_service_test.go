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
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	ariesmockstorage "github.com/trustbloc/did-go/legacy/mock/storage"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmskeytypes "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/ecdsa2019"
	"github.com/trustbloc/vc-go/verifiable"

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
			createVC(t, verifiable.CredentialContents{
				Subject: []verifiable.Subject{{
					ID: "",
					CustomFields: map[string]interface{}{
						"statusListIndex": "1",
						"statusPurpose":   "2",
						"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
					},
				}},
				Issuer: &verifiable.Issuer{
					ID: "did:trustblock:abc",
				},
			}), nil)

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
			mockVDRRegistry := &vdrmock.VDRegistry{}
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
					createVC(t, verifiable.CredentialContents{
						Subject: []verifiable.Subject{{
							ID: "",
							CustomFields: map[string]interface{}{
								"statusListIndex": "1",
								"statusPurpose":   "2",
								"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
							},
						}},
						Issuer: &verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}), nil)

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
					createVC(t, verifiable.CredentialContents{
						Subject: []verifiable.Subject{{
							ID: "",
							CustomFields: map[string]interface{}{
								"statusListIndex": "1",
								"statusPurpose":   "2",
								"encodedList":     "H4sIAAAAAAAA_2ICBAAA__-hjgw8AQAAAA",
							},
						}},
						Issuer: &verifiable.Issuer{
							ID: "did:trustblock:abc",
						},
					}), nil)

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
		issuer      *verifiable.Issuer
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
						"https://example.com/status/1").AnyTimes().Return(
						createVC(t, verifiable.CredentialContents{
							Subject: []verifiable.Subject{{
								ID: "",
								CustomFields: map[string]interface{}{
									"statusListIndex": "1",
									"statusPurpose":   "2",
									"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
								},
							}},
							Issuer: &verifiable.Issuer{
								ID: "did:trustblock:abc",
							},
						}), nil)

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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
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
						createVC(t, verifiable.CredentialContents{
							Subject: []verifiable.Subject{},
							Issuer: &verifiable.Issuer{
								ID: "did:trustblock:123",
							},
						}), nil)

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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
			},
			wantErr: true,
		},
		{
			name: "revocationListVC invalid subject field error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						createVC(t, verifiable.CredentialContents{
							Subject: []verifiable.Subject{},
							Issuer: &verifiable.Issuer{
								ID: "did:trustblock:abc",
							},
						}), nil)

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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
			},
			wantErr: true,
		},
		{
			name: "revocationListVC invalid encodedList field error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						createVC(t, verifiable.CredentialContents{
							Subject: []verifiable.Subject{{
								ID: "",
								CustomFields: map[string]interface{}{
									"statusListIndex": "1",
									"statusPurpose":   "2",
									"encodedList":     "",
								},
							}},
							Issuer: &verifiable.Issuer{
								ID: "did:trustblock:abc",
							},
						}), nil)

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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
			},
			wantErr: true,
		},
		{
			name: "revocationListVC bitString.Get() error",
			fields: fields{
				getStatusListVCGetter: func() statusListVCURIResolver {
					mockStatusListVCGetter := NewMockStatusListVCResolver(gomock.NewController(t))
					mockStatusListVCGetter.EXPECT().Resolve(context.Background(), gomock.Any()).AnyTimes().Return(
						createVC(t, verifiable.CredentialContents{
							Subject: []verifiable.Subject{{
								ID: "",
								CustomFields: map[string]interface{}{
									"statusListIndex": "1",
									"statusPurpose":   "2",
									"encodedList":     "H4sIAAAAAAAA_2IABAAA__-N7wLSAQAAAA",
								},
							}},
							Issuer: &verifiable.Issuer{
								ID: "did:trustblock:abc",
							},
						}), nil)

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
				issuer: &verifiable.Issuer{ID: "did:trustblock:abc"},
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
		credential       *verifiable.Credential
		proofChallenge   string
		proofDomain      string
		vcInVPValidation bool
		isJWT            bool
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ProofChallenge invalid value",
			args: args{
				credential:       signedVC,
				proofChallenge:   "some value",
				vcInVPValidation: false,
			},
			wantErr: true,
		},
		{
			name: "ProofDomain invalid value",
			args: args{
				credential:       signedVC,
				proofChallenge:   crypto.Challenge,
				proofDomain:      "some value",
				vcInVPValidation: false,
			},
			wantErr: true,
		},
		{
			name: "ProofDomain JWT invalid value",
			args: args{
				credential:       signedVC,
				proofChallenge:   crypto.Challenge,
				proofDomain:      "some value",
				vcInVPValidation: false,
				isJWT:            true,
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
				tt.args.credential,
				tt.args.proofChallenge,
				tt.args.proofDomain,
				tt.args.vcInVPValidation,
				!tt.args.isJWT); (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentialProof() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_DataIntegrity_SignVerify(t *testing.T) {
	vcJSON := `
	{
	 "@context": [
	   "https://www.w3.org/2018/credentials/v1",
	   "https://www.w3.org/2018/credentials/examples/v1",
		"https://w3id.org/security/data-integrity/v1"
	 ],
	 "id": "https://example.com/credentials/1872",
	 "type": [
	   "VerifiableCredential",
	   "UniversityDegreeCredential"
	 ],
	 "issuer": "did:foo:bar",
	 "issuanceDate": "2020-01-17T15:14:09.724Z",
	 "credentialSubject": {
	   "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	   "degree": {
	     "type": "BachelorDegree"
	   },
	   "name": "Jayden Doe",
	   "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	 }
	}
	`
	localSuite := createKMS(t)

	signer, err := localSuite.KMSCrypto()
	require.NoError(t, err)

	key, err := signer.Create(kmskeytypes.ECDSAP256IEEEP1363)
	require.NoError(t, err)

	const signingDID = "did:foo:bar"

	const vmID = "#key-1"

	docLoader := testutil.DocumentLoader(t)

	verificationMethod, err := did.NewVerificationMethodFromJWK(signingDID+vmID, "JsonWebKey2020", signingDID, key)
	require.NoError(t, err)

	didResolver := &vdrmock.VDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return makeMockDIDResolution(signingDID, verificationMethod, did.AssertionMethod), nil
		}}

	signerSuite := ecdsa2019.NewSignerInitializer(&ecdsa2019.SignerInitializerOptions{
		SignerGetter:     ecdsa2019.WithKMSCryptoWrapper(signer),
		LDDocumentLoader: docLoader,
	})

	diSigner, err := dataintegrity.NewSigner(&dataintegrity.Options{
		DIDResolver: didResolver,
	}, signerSuite)
	require.NoError(t, err)

	signContext := &verifiable.DataIntegrityProofContext{
		SigningKeyID: signingDID + vmID,
		ProofPurpose: crypto.AssertionMethod,
		CryptoSuite:  ecdsa2019.SuiteType,
		Created:      nil,
		Domain:       "mock-domain",
		Challenge:    "mock-challenge",
	}

	var vcParsed *verifiable.Credential
	vcParsed, err = verifiable.ParseCredential([]byte(vcJSON),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(docLoader))
	require.NoError(t, err)

	err = vcParsed.AddDataIntegrityProof(signContext, diSigner)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		s := &Service{
			documentLoader: docLoader,
			vdr:            didResolver,
		}

		if err = s.ValidateCredentialProof(
			context.Background(),
			vcParsed,
			"mock-challenge",
			"mock-domain",
			false,
			true); err != nil {
			t.Errorf("ValidateCredentialProof() error = %v", err)
		}
	})
}

func makeMockDIDResolution(id string, vm *did.VerificationMethod, vr did.VerificationRelationship) *did.DocResolution {
	ver := []did.Verification{{
		VerificationMethod: *vm,
		Relationship:       vr,
	}}

	doc := &did.Doc{
		ID: id,
	}

	switch vr { //nolint:exhaustive
	case did.VerificationRelationshipGeneral:
		doc.VerificationMethod = []did.VerificationMethod{*vm}
	case did.Authentication:
		doc.Authentication = ver
	case did.AssertionMethod:
		doc.AssertionMethod = ver
	}

	return &did.DocResolution{
		DIDDocument: doc,
	}
}

func createKMS(t *testing.T) api.Suite {
	t.Helper()

	store, err := kms.NewAriesProviderWrapper(ariesmockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	localSuite, err := localsuite.NewLocalCryptoSuite("local-lock://custom/primary/key/", store, &noop.NoLock{})
	require.NoError(t, err)

	return localSuite
}
func createVC(t *testing.T, vcc verifiable.CredentialContents) *verifiable.Credential {
	vc, err := verifiable.CreateCredential(vcc, nil)
	require.NoError(t, err)

	return vc
}
