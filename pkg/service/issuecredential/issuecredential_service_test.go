/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

func TestService_IssueCredential(t *testing.T) {
	t.Parallel()

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
		&mockVCSKeyManager{crypto: customCrypto, kms: customKMS}, nil)

	mockVCStore := NewMockVCStore(gomock.NewController(t))
	mockVCStore.EXPECT().Put(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

	mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))
	mockVCStatusManager.EXPECT().CreateStatusID(gomock.Any(), gomock.Any()).AnyTimes().Return(&verifiable.TypedID{
		ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
		Type: "JsonSchemaValidator2018",
	}, nil)
	mockVCStatusManager.EXPECT().GetCredentialStatusURL(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		Return("", nil)

	t.Run("Success LDP", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name string
			kt   kms.KeyType
			sr   verifiable.SignatureRepresentation
		}{
			{
				name: "OK ED25519",
				kt:   kms.ED25519Type,
			},
			{
				name: "OK ECDSA P256",
				kt:   kms.ECDSAP256TypeIEEEP1363,
			},
			{
				name: "OK ECDSA P384",
				kt:   kms.ECDSAP384TypeIEEEP1363,
			},
			{
				name: "OK ECDSA P521",
				kt:   kms.ECDSAP521TypeIEEEP1363,
			},
		}

		for _, ktTestCase := range tests {
			t.Run(ktTestCase.name, func(t *testing.T) {
				tests := []struct {
					name string
					sr   verifiable.SignatureRepresentation
				}{
					{
						name: "OK JWS",
						sr:   verifiable.SignatureJWS,
					},
					{
						name: "OK ProofValue",
						sr:   verifiable.SignatureProofValue,
					},
				}
				for _, sigRepresentationTextCase := range tests {
					t.Run(sigRepresentationTextCase.name, func(t *testing.T) {
						keyID, _, err := customKMS.CreateAndExportPubKeyBytes(ktTestCase.kt)
						require.NoError(t, err)

						didDoc := createDIDDoc("did:trustblock:abc", keyID)
						crypto := vccrypto.New(
							&vdrmock.MockVDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

						service := New(&Config{
							VCStatusManager: mockVCStatusManager,
							Crypto:          crypto,
							KMSRegistry:     kmsRegistry,
							VCStore:         mockVCStore,
						})

						verifiableCredentials, err := service.IssueCredential(
							&verifiable.Credential{},
							nil,
							&profileapi.Issuer{
								VCConfig: &profileapi.VCConfig{
									SigningAlgorithm:        vcs.JSONWebSignature2020,
									SignatureRepresentation: sigRepresentationTextCase.sr,
									Format:                  vcs.Ldp,
								},
								SigningDID: &profileapi.SigningDID{
									DID:     didDoc.ID,
									Creator: didDoc.VerificationMethod[0].ID,
								}},
						)
						require.NoError(t, err)
						validateVC(t, verifiableCredentials, didDoc, sigRepresentationTextCase.sr, vcs.Ldp)
					})
				}
			})
		}
	})

	t.Run("Success JWT", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name string
			kt   kms.KeyType
			sr   verifiable.SignatureRepresentation
		}{
			{
				name: "OK ED25519",
				kt:   kms.ED25519Type,
			},
			{
				name: "OK ECDSA P256",
				kt:   kms.ECDSAP256TypeIEEEP1363,
			},
			{
				name: "OK ECDSA P384",
				kt:   kms.ECDSAP384TypeIEEEP1363,
			},
			{
				name: "OK ECDSA P521",
				kt:   kms.ECDSAP521TypeIEEEP1363,
			},
		}

		for _, ktTestCase := range tests {
			t.Run(ktTestCase.name, func(t *testing.T) {
				keyID, _, err := customKMS.CreateAndExportPubKeyBytes(ktTestCase.kt)
				require.NoError(t, err)

				didDoc := createDIDDoc("did:trustblock:abc", keyID)
				crypto := vccrypto.New(
					&vdrmock.MockVDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

				service := New(&Config{
					VCStatusManager: mockVCStatusManager,
					Crypto:          crypto,
					KMSRegistry:     kmsRegistry,
					VCStore:         mockVCStore,
				})

				verifiableCredentials, err := service.IssueCredential(
					&verifiable.Credential{
						ID:      "http://example.edu/credentials/1872",
						Context: []string{verifiable.ContextURI},
						Types:   []string{verifiable.VCType},
						Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						Issued: &util.TimeWrapper{
							Time: time.Now(),
						},
						Issuer: verifiable.Issuer{
							ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
						},
						CustomFields: map[string]interface{}{
							"first_name": "First name",
							"last_name":  "Last name",
							"info":       "Info",
						},
					},
					nil,
					&profileapi.Issuer{
						VCConfig: &profileapi.VCConfig{
							SigningAlgorithm: vcs.JSONWebSignature2020,
							Format:           vcs.Jwt,
							KeyType:          ktTestCase.kt,
						},
						SigningDID: &profileapi.SigningDID{
							DID:     didDoc.ID,
							Creator: didDoc.VerificationMethod[0].ID,
						}},
				)
				require.NoError(t, err)
				validateVC(t, verifiableCredentials, didDoc, 0, vcs.Jwt)
			})
		}
	})

	t.Run("Error kmsRegistry", func(t *testing.T) {
		registry := NewMockKMSRegistry(gomock.NewController(t))
		registry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("some error"))

		service := New(&Config{
			KMSRegistry: registry,
		})

		verifiableCredentials, err := service.IssueCredential(
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{})
		require.Error(t, err)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Error VCStatusManager.CreateStatusID", func(t *testing.T) {
		registry := NewMockKMSRegistry(gomock.NewController(t))
		registry.EXPECT().GetKeyManager(gomock.Any()).Return(nil, nil)

		vcStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		vcStatusManager.EXPECT().CreateStatusID(gomock.Any(), gomock.Any()).Return(nil, errors.New("some error"))
		vcStatusManager.EXPECT().GetCredentialStatusURL(gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)

		service := New(&Config{
			KMSRegistry:     registry,
			VCStatusManager: vcStatusManager,
		})

		verifiableCredentials, err := service.IssueCredential(
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{
				SigningDID: &profileapi.SigningDID{},
				VCConfig: &profileapi.VCConfig{
					Format: vcs.Ldp,
				}})
		require.Error(t, err)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Error VCStatusManager.GetCredentialStatusURL", func(t *testing.T) {
		registry := NewMockKMSRegistry(gomock.NewController(t))
		registry.EXPECT().GetKeyManager(gomock.Any()).Return(nil, nil)

		vcStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		vcStatusManager.EXPECT().GetCredentialStatusURL(gomock.Any(), gomock.Any(), gomock.Any()).
			Return("", errors.New("some error"))

		service := New(&Config{
			KMSRegistry:     registry,
			VCStatusManager: vcStatusManager,
		})

		verifiableCredentials, err := service.IssueCredential(
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{
				SigningDID: &profileapi.SigningDID{},
				VCConfig: &profileapi.VCConfig{
					Format: vcs.Ldp,
				}})
		require.Error(t, err)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Error Crypto", func(t *testing.T) {
		kmRegistry := NewMockKMSRegistry(gomock.NewController(t))
		kmRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, nil)

		vcStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		vcStatusManager.EXPECT().CreateStatusID(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, nil)
		vcStatusManager.EXPECT().GetCredentialStatusURL(gomock.Any(), gomock.Any(), gomock.Any()).Return("", nil)

		cr := NewMockvcCrypto(gomock.NewController(t))
		cr.EXPECT().SignCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("some error"))
		service := New(&Config{
			KMSRegistry:     kmRegistry,
			VCStatusManager: vcStatusManager,
			Crypto:          cr,
		})

		verifiableCredentials, err := service.IssueCredential(
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{
				SigningDID: &profileapi.SigningDID{},
				VCConfig: &profileapi.VCConfig{
					Format: vcs.Ldp,
				}})
		require.Error(t, err)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Error unknown signature format", func(t *testing.T) {
		kmRegistry := NewMockKMSRegistry(gomock.NewController(t))
		kmRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, nil)

		vcStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		vcStatusManager.EXPECT().CreateStatusID(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, nil)
		vcStatusManager.EXPECT().GetCredentialStatusURL(
			gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return("", nil)

		keyID, _, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		didDoc := createDIDDoc("did:trustblock:abc", keyID)
		crypto := vccrypto.New(
			&vdrmock.MockVDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

		service := New(&Config{
			KMSRegistry:     kmRegistry,
			VCStatusManager: vcStatusManager,
			Crypto:          crypto,
		})

		verifiableCredentials, err := service.IssueCredential(
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{
				SigningDID: &profileapi.SigningDID{},
				VCConfig: &profileapi.VCConfig{
					Format: "invalid value",
				}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown signature format")
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Error store", func(t *testing.T) {
		keyID, _, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		didDoc := createDIDDoc("did:trustblock:abc", keyID)
		crypto := vccrypto.New(
			&vdrmock.MockVDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

		failedStore := NewMockVCStore(gomock.NewController(t))
		failedStore.EXPECT().Put(gomock.Any(), gomock.Any()).AnyTimes().Return(errors.New("some error"))

		service := New(&Config{
			VCStatusManager: mockVCStatusManager,
			Crypto:          crypto,
			KMSRegistry:     kmsRegistry,
			VCStore:         failedStore,
		})

		verifiableCredentials, err := service.IssueCredential(
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{
				VCConfig: &profileapi.VCConfig{
					SigningAlgorithm:        vcs.JSONWebSignature2020,
					SignatureRepresentation: verifiable.SignatureProofValue,
					Format:                  vcs.Ldp,
				},
				SigningDID: &profileapi.SigningDID{
					DID:     didDoc.ID,
					Creator: didDoc.VerificationMethod[0].ID,
				}},
		)
		require.Error(t, err)
		require.Nil(t, verifiableCredentials)
	})
}

func validateVC(
	t *testing.T, vc *verifiable.Credential,
	did *did.Doc,
	sigRepresentation verifiable.SignatureRepresentation,
	vcFormat vcs.Format) {
	t.Helper()

	require.NotNil(t, vc)
	require.NotNil(t, vc.Issuer)
	require.Equal(t, "did:trustblock:abc", vc.Issuer.ID)

	if vcFormat == vcs.Jwt {
		require.NotEmpty(t, vc.JWT)
		return
	}

	require.Len(t, vc.Proofs, 1)
	verificationMethod, ok := vc.Proofs[0]["verificationMethod"]
	require.True(t, ok)
	require.Equal(t, verificationMethod, did.VerificationMethod[0].ID)
	switch sigRepresentation {
	case verifiable.SignatureProofValue:
		proofValue, ok := vc.Proofs[0]["proofValue"]
		require.True(t, ok)
		require.NotEmpty(t, proofValue)
		jws, ok := vc.Proofs[0]["jws"]
		require.False(t, ok)
		require.Empty(t, jws)
	case verifiable.SignatureJWS:
		proofValue, ok := vc.Proofs[0]["proofValue"]
		require.False(t, ok)
		require.Empty(t, proofValue)
		jws, ok := vc.Proofs[0]["jws"]
		require.True(t, ok)
		require.NotEmpty(t, jws)
	}
}

func createDIDDoc(didID, keyID string) *did.Doc { //nolint:unparam
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	creator := fmt.Sprintf("%s#%s", didID, keyID)

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: model.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
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

type mockVCSKeyManager struct {
	crypto ariescrypto.Crypto
	kms    *localkms.LocalKMS
}

func (m *mockVCSKeyManager) NewVCSigner(creator string, signatureType vcs.SignatureType) (vc.SignerAlgorithm, error) {
	return signer.NewKMSSigner(m.kms, m.crypto, creator, signatureType, nil)
}

func (m *mockVCSKeyManager) SupportedKeyTypes() []kms.KeyType {
	return nil
}
func (m *mockVCSKeyManager) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}
func (m *mockVCSKeyManager) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	return "", nil, nil
}
