/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/did/endpoint"
	util "github.com/trustbloc/did-go/doc/util/time"
	ariesmockstorage "github.com/trustbloc/did-go/legacy/mock/storage"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/kms/localkms"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	ariescrypto "github.com/trustbloc/kms-go/spi/crypto"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/vc/vcutil"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestService_IssueCredential(t *testing.T) {
	t.Parallel()

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
		&mockVCSKeyManager{crypto: customCrypto, kms: customKMS}, nil)

	ctx := context.Background()

	mockVCStatusManager := NewMockVCStatusManager(gomock.NewController(t))
	mockVCStatusManager.EXPECT().CreateStatusListEntry(ctx, gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
		&credentialstatus.StatusListEntry{
			Context: "https://w3id.org/vc-revocation-list-2020/v1",
			TypedID: &verifiable.TypedID{
				ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
				Type: string(vc.RevocationList2020VCStatus),
			},
		}, nil)

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
							&vdrmock.VDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

						service := issuecredential.New(&issuecredential.Config{
							VCStatusManager: mockVCStatusManager,
							Crypto:          crypto,
							KMSRegistry:     kmsRegistry,
						})

						verifiableCredentials, err := service.IssueCredential(
							ctx,
							getVC(t),
							nil,
							&profileapi.Issuer{
								VCConfig: &profileapi.VCConfig{
									SigningAlgorithm:        vcs.JSONWebSignature2020,
									SignatureRepresentation: sigRepresentationTextCase.sr,
									Format:                  vcs.Ldp,
								},
								SigningDID: &profileapi.SigningDID{
									DID:      didDoc.ID,
									Creator:  didDoc.VerificationMethod[0].ID,
									KMSKeyID: keyID,
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
					&vdrmock.VDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

				service := issuecredential.New(&issuecredential.Config{
					VCStatusManager: mockVCStatusManager,
					Crypto:          crypto,
					KMSRegistry:     kmsRegistry,
				})

				verifiableCredentials, err := service.IssueCredential(
					ctx,
					getVC(t),
					nil,
					&profileapi.Issuer{
						VCConfig: &profileapi.VCConfig{
							SigningAlgorithm: vcs.JSONWebSignature2020,
							Format:           vcs.Jwt,
							KeyType:          ktTestCase.kt,
						},
						SigningDID: &profileapi.SigningDID{
							DID:      didDoc.ID,
							Creator:  didDoc.VerificationMethod[0].ID,
							KMSKeyID: keyID,
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

		service := issuecredential.New(&issuecredential.Config{
			KMSRegistry: registry,
		})

		verifiableCredentials, err := service.IssueCredential(
			ctx,
			&verifiable.Credential{},
			nil,
			&profileapi.Issuer{})
		require.Error(t, err)
		require.Nil(t, verifiableCredentials)
	})
	t.Run("Error VCStatusManager.CreateStatusListEntry", func(t *testing.T) {
		registry := NewMockKMSRegistry(gomock.NewController(t))
		registry.EXPECT().GetKeyManager(gomock.Any()).Return(nil, nil)

		vcStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		vcStatusManager.EXPECT().CreateStatusListEntry(
			ctx, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("some error"))

		service := issuecredential.New(&issuecredential.Config{
			KMSRegistry:     registry,
			VCStatusManager: vcStatusManager,
		})

		verifiableCredentials, err := service.IssueCredential(
			ctx,
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
	t.Run("Error DataProtector", func(t *testing.T) {
		kmRegistry := NewMockKMSRegistry(gomock.NewController(t))
		kmRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, nil)

		vcStatusManager := NewMockVCStatusManager(gomock.NewController(t))
		vcStatusManager.EXPECT().CreateStatusListEntry(ctx, gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
			&credentialstatus.StatusListEntry{
				Context: vcutil.DefVCContext,
				TypedID: &verifiable.TypedID{
					ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Type: "JsonSchemaValidator2018",
				},
			}, nil)

		cr := NewMockvcCrypto(gomock.NewController(t))
		cr.EXPECT().SignCredential(gomock.Any(), gomock.Any(), gomock.Any()).Return(
			nil, errors.New("some error"))
		service := issuecredential.New(&issuecredential.Config{
			KMSRegistry:     kmRegistry,
			VCStatusManager: vcStatusManager,
			Crypto:          cr,
		})

		verifiableCredentials, err := service.IssueCredential(
			ctx,
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
		vcStatusManager.EXPECT().CreateStatusListEntry(ctx, gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(
			&credentialstatus.StatusListEntry{
				Context: vcutil.DefVCContext,
				TypedID: &verifiable.TypedID{
					ID:   "https://www.w3.org/TR/vc-data-model/3.0/#types",
					Type: "JsonSchemaValidator2018",
				},
			}, nil)

		keyID, _, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		didDoc := createDIDDoc("did:trustblock:abc", keyID)
		crypto := vccrypto.New(
			&vdrmock.VDRegistry{ResolveValue: didDoc}, testutil.DocumentLoader(t))

		service := issuecredential.New(&issuecredential.Config{
			KMSRegistry:     kmRegistry,
			VCStatusManager: vcStatusManager,
			Crypto:          crypto,
		})

		verifiableCredentials, err := service.IssueCredential(
			ctx,
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
}

func getVC(t *testing.T) *verifiable.Credential {
	t.Helper()

	vc, err := verifiable.CreateCredential(verifiable.CredentialContents{
		ID:      "http://example.edu/credentials/1872",
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Subject: []verifiable.Subject{{ID: "did:example:76e12ec712ebc6f1c221ebfeb1f"}},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: &verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
	}, map[string]interface{}{
		"first_name": "First name",
		"last_name":  "Last name",
		"info":       "Info",
	})
	require.NoError(t, err)

	return vc
}

func validateVC(
	t *testing.T, vc *verifiable.Credential,
	did *did.Doc,
	sigRepresentation verifiable.SignatureRepresentation,
	vcFormat vcs.Format) {
	t.Helper()
	require.NotNil(t, vc)

	vcc := vc.Contents()
	require.NotNil(t, vcc.Issuer)
	require.Equal(t, "did:trustblock:abc", vcc.Issuer.ID)
	require.True(t, strings.HasPrefix(vcc.ID, "urn:uuid:"))

	if vcFormat == vcs.Jwt {
		require.True(t, vc.IsJWT())
		return
	}

	require.Len(t, vc.Proofs(), 1)
	verificationMethod, ok := vc.Proofs()[0]["verificationMethod"]
	require.True(t, ok)
	require.Equal(t, verificationMethod, did.VerificationMethod[0].ID)
	switch sigRepresentation {
	case verifiable.SignatureProofValue:
		proofValue, ok := vc.Proofs()[0]["proofValue"]
		require.True(t, ok)
		require.NotEmpty(t, proofValue)
		jws, ok := vc.Proofs()[0]["jws"]
		require.False(t, ok)
		require.Empty(t, jws)
	case verifiable.SignatureJWS:
		proofValue, ok := vc.Proofs()[0]["proofValue"]
		require.False(t, ok)
		require.Empty(t, proofValue)
		jws, ok := vc.Proofs()[0]["jws"]
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
		ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://agent.example.com/"),
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
func (m *mockVCSKeyManager) CreateJWKKey(_ kms.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}
func (m *mockVCSKeyManager) CreateCryptoKey(_ kms.KeyType) (string, interface{}, error) {
	return "", nil, nil
}
