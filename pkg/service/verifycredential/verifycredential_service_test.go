/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifycredential

import (
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	kmskeytypes "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"

	vcformats "github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
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
		Credential: &verifier.CredentialChecks{
			Proof: true,
			Format: []vcformats.Format{
				vcformats.JwtVC,
				vcformats.LdpVC,
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
		OIDCConfig:     map[string]interface{}{"config": "value"},
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

		customKMS := createKMS(t)

		customCrypto, err := tinkcrypto.New()
		require.NoError(t, err)

		created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
		require.NoError(t, err)

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
							vcFile string
						}{
							{
								name:   "Credential format JWT",
								vcFile: sampleVCJWT,
							},
							{
								name:   "Credential format JSON-LD",
								vcFile: sampleVCJsonLD,
							},
						}
						for _, vcFileTestCase := range tests {
							t.Run(vcFileTestCase.name, func(t *testing.T) {
								// Assert
								vc, err := verifiable.ParseCredential(
									[]byte(vcFileTestCase.vcFile),
									verifiable.WithDisabledProofCheck(),
									verifiable.WithJSONLDDocumentLoader(loader))
								require.NoError(t, err)

								keyID, kh, err := customKMS.Create(ktTestCase.kt)
								require.NoError(t, err)

								pkBytes, _, err := customKMS.ExportPubKeyBytes(keyID)
								require.NoError(t, err)

								didDoc := createDIDDoc(t, "did:trustblock:abc", keyID, pkBytes, ktTestCase.kt)
								mockVDRRegistry := &vdrmock.MockVDRegistry{
									ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
										return &did.DocResolution{DIDDocument: didDoc}, nil
									},
								}

								// Sign
								signerSuite := jsonwebsignature2020.New(
									suite.WithSigner(suite.NewCryptoSigner(customCrypto, kh)))
								err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
									SignatureType:           "JsonWebSignature2020",
									Suite:                   signerSuite,
									SignatureRepresentation: sigRepresentationTextCase.sr,
									Created:                 &created,
									VerificationMethod:      didDoc.VerificationMethod[0].ID,
									Domain:                  domain,
									Challenge:               challenge,
									Purpose:                 vccrypto.AssertionMethod,
								}, jsonld.WithDocumentLoader(loader))
								require.NoError(t, err)

								// Verify
								op := New(&Config{
									VcStatusManager: mockVCStatusManager,
									VDR:             mockVDRRegistry,
									DocumentLoader:  loader,
								})

								res, err := op.VerifyCredential(vc, &Options{
									Challenge: challenge,
									Domain:    domain,
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
		mockVDRRegistry := &vdrmock.MockVDRegistry{}
		loader := testutil.DocumentLoader(t)
		vc, err := verifiable.ParseCredential(
			[]byte(sampleVCJsonLD),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		service := New(&Config{
			VcStatusManager: mockVCStatusManager,
			VDR:             mockVDRRegistry,
			DocumentLoader:  loader,
		})

		t.Run("Proof", func(t *testing.T) {
			res, err := service.VerifyCredential(vc, &Options{
				Challenge: challenge,
				Domain:    domain,
			}, testProfile)

			require.NoError(t, err)
			require.Len(t, res, 1)
		})

		t.Run("Proof and Status", func(t *testing.T) {
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
			op := New(&Config{
				VcStatusManager: failedMockVCStatusManager,
				VDR:             mockVDRRegistry,
				DocumentLoader:  loader,
			})
			res, err := op.VerifyCredential(vc, &Options{
				Challenge: challenge,
				Domain:    domain,
			}, testProfile)

			require.NoError(t, err)
			require.Len(t, res, 2)
		})

		t.Run("Status", func(t *testing.T) {
			vc.Status = nil
			res, err := service.VerifyCredential(vc, &Options{
				Challenge: challenge,
				Domain:    domain,
			}, testProfile)

			require.Error(t, err)
			require.Nil(t, res)
		})
	})
}

func createDIDDoc(t *testing.T, didID, keyID string, pubKeyBytes []byte, kt kmskeytypes.KeyType) *did.Doc {
	t.Helper()

	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "JsonWebKey2020"
	)

	creator := fmt.Sprintf("%s#%s", didID, keyID)

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: model.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	j, _ := jwksupport.PubKeyBytesToJWK(pubKeyBytes, kt)

	mv, _ := did.NewVerificationMethodFromJWK(creator, keyType, "", j)

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{*mv},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: *mv}},
		Authentication:       []did.Verification{{VerificationMethod: *mv}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: *mv}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: *mv}},
	}
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p, err := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
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
		want    *VerificationStatus
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
			want: &VerificationStatus{
				Verified: true,
				Message:  "success",
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
			want:    nil,
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
			want:    nil,
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
			want:    nil,
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
			want:    nil,
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
			want:    nil,
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
			want:    nil,
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
			want:    nil,
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
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vcStatusManager: tt.fields.getVCStatusManager(),
			}
			got, err := s.checkVCStatus(tt.args.getVcStatus(), tt.args.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkVCStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkVCStatus() got = %v, want %v", got, tt.want)
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
