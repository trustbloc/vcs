/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp_test

import (
	"context"
	"crypto"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	arieskms "github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	"github.com/trustbloc/vc-go/proof/testsupport"

	"github.com/trustbloc/did-go/doc/did"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	lddocloader "github.com/trustbloc/did-go/doc/ld/documentloader"
	util "github.com/trustbloc/did-go/doc/util/time"
	ariesmockstorage "github.com/trustbloc/did-go/legacy/mock/storage"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"
	"github.com/trustbloc/kms-go/doc/util/fingerprint"
	"github.com/trustbloc/kms-go/secretlock/noop"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/mock/vcskms"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

var (
	//go:embed testdata/university_degree.jsonld
	sampleVCJsonLD string
	//go:embed testdata/university_degree.jwt
	sampleVCJWT string
)

const (
	profileID             = "testProfileID"
	profileVersion        = "v1.0"
	customScope           = "customScope"
	presentationPolicyURL = "https://trust-registry.dev/verifier/policies/{policyID}/{policyVersion}/interactions/presentation" //nolint:lll
)

func TestService_InitiateOidcInteraction(t *testing.T) {
	cryptoSuite := createCryptoSuite(t)

	keyCreator, err := cryptoSuite.KeyCreator()
	require.NoError(t, err)

	customSigner, err := cryptoSuite.KMSCryptoMultiSigner()
	require.NoError(t, err)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
		&vcskms.MockKMS{Signer: customSigner}, nil)

	txManager := NewMockTransactionManager(gomock.NewController(t))
	txManager.EXPECT().CreateTx(gomock.Any(), gomock.Any(), gomock.Any(), []string{customScope}).AnyTimes().
		Return(&oidc4vp.Transaction{
			ID:                     "TxID1",
			ProfileID:              "test4",
			PresentationDefinition: &presexch.PresentationDefinition{},
			CustomScopes:           []string{customScope},
		}, "nonce1", nil)
	requestObjectPublicStore := NewMockRequestObjectPublicStore(gomock.NewController(t))
	requestObjectPublicStore.EXPECT().Publish(gomock.Any(), gomock.Any()).
		AnyTimes().DoAndReturn(func(ctx context.Context, token string) (string, error) {
		return "someurl/abc", nil
	})

	s := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:                 &mockEvent{},
		EventTopic:               spi.VerifierEventTopic,
		TransactionManager:       txManager,
		RequestObjectPublicStore: requestObjectPublicStore,
		KMSRegistry:              kmsRegistry,
		RedirectURL:              "test://redirect",
		TokenLifetime:            time.Second * 100,
	})

	pubKey, err := keyCreator.Create(kms.ED25519Type)
	require.NoError(t, err)

	correctProfile := &profileapi.Verifier{
		ID:             "test1",
		Name:           "test2",
		URL:            "test3",
		Active:         true,
		OrganizationID: "test4",
		OIDCConfig: &profileapi.OIDC4VPConfig{
			KeyType: kms.ED25519Type,
		},
		Checks: &profileapi.VerificationChecks{
			Credential: profileapi.CredentialChecks{
				Proof: false,
				Format: []vcsverifiable.Format{
					vcsverifiable.Jwt,
				},
			},
			Presentation: &profileapi.PresentationChecks{
				Format: []vcsverifiable.Format{
					vcsverifiable.Jwt,
				},
			},
		},
		SigningDID: &profileapi.SigningDID{
			DID:      "did:test:acde",
			Creator:  "did:test:acde#" + pubKey.KeyID,
			KMSKeyID: pubKey.KeyID,
		},
	}

	t.Run("Success", func(t *testing.T) {
		info, err := s.InitiateOidcInteraction(context.TODO(), &presexch.PresentationDefinition{
			ID: "test",
		}, "test", []string{customScope}, correctProfile)

		require.NoError(t, err)
		require.NotNil(t, info)
	})

	t.Run("No signature did", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.SigningDID = nil

		info, err := s.InitiateOidcInteraction(
			context.TODO(), &presexch.PresentationDefinition{}, "test", []string{customScope}, incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("Tx create failed", func(t *testing.T) {
		txManagerErr := NewMockTransactionManager(gomock.NewController(t))
		txManagerErr.EXPECT().CreateTx(
			gomock.Any(), gomock.Any(), gomock.Any(), []string{customScope}).AnyTimes().Return(nil, "", errors.New("fail"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:                 &mockEvent{},
			EventTopic:               spi.VerifierEventTopic,
			TransactionManager:       txManagerErr,
			RequestObjectPublicStore: requestObjectPublicStore,
			KMSRegistry:              kmsRegistry,
			RedirectURL:              "test://redirect",
		})

		info, err := withError.InitiateOidcInteraction(
			context.TODO(),
			&presexch.PresentationDefinition{},
			"test",
			[]string{customScope},
			correctProfile,
		)

		require.Contains(t, err.Error(), "create oidc tx")
		require.Nil(t, info)
	})

	t.Run("publish request object failed", func(t *testing.T) {
		requestObjectPublicStoreErr := NewMockRequestObjectPublicStore(gomock.NewController(t))
		requestObjectPublicStoreErr.EXPECT().Publish(gomock.Any(), gomock.Any()).
			AnyTimes().Return("", errors.New("fail"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:                 &mockEvent{},
			EventTopic:               spi.VerifierEventTopic,
			TransactionManager:       txManager,
			RequestObjectPublicStore: requestObjectPublicStoreErr,
			KMSRegistry:              kmsRegistry,
			RedirectURL:              "test://redirect",
		})

		info, err := withError.InitiateOidcInteraction(
			context.TODO(),
			&presexch.PresentationDefinition{},
			"test",
			[]string{customScope},
			correctProfile,
		)

		require.Contains(t, err.Error(), "publish request object")
		require.Nil(t, info)
	})

	t.Run("fail to get kms form registry", func(t *testing.T) {
		kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
		kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("fail"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:                 &mockEvent{},
			EventTopic:               spi.VerifierEventTopic,
			TransactionManager:       txManager,
			RequestObjectPublicStore: requestObjectPublicStore,
			KMSRegistry:              kmsRegistry,
			RedirectURL:              "test://redirect",
		})

		info, err := withError.InitiateOidcInteraction(
			context.TODO(),
			&presexch.PresentationDefinition{},
			"test",
			[]string{customScope},
			correctProfile,
		)

		require.Contains(t, err.Error(), "get key manager")
		require.Nil(t, info)
	})

	t.Run("Invalid key", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.SigningDID.KMSKeyID = "invalid"

		info, err := s.InitiateOidcInteraction(
			context.TODO(), &presexch.PresentationDefinition{}, "test", []string{customScope}, incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("Invalid key type", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.OIDCConfig.KeyType = "invalid"

		info, err := s.InitiateOidcInteraction(
			context.TODO(), &presexch.PresentationDefinition{}, "test", []string{customScope}, incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})
}

func TestService_VerifyOIDCVerifiablePresentation(t *testing.T) {
	cryptoSuite := createCryptoSuite(t)

	w, err := cryptoSuite.KMSCrypto()
	require.NoError(t, err)

	txManager := NewMockTransactionManager(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))
	presentationVerifier := NewMockPresentationVerifier(gomock.NewController(t))
	trustRegistry := NewMockTrustRegistryService(gomock.NewController(t))

	vp, pd, issuer, vdr, loader := newVPWithPD(t, w)

	s := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:             &mockEvent{},
		EventTopic:           spi.VerifierEventTopic,
		TransactionManager:   txManager,
		PresentationVerifier: presentationVerifier,
		ProfileService:       profileService,
		DocumentLoader:       loader,
		VDR:                  vdr,
		TrustRegistryService: trustRegistry,
	})

	txManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
		ID:                     "txID1",
		ProfileID:              profileID,
		ProfileVersion:         profileVersion,
		PresentationDefinition: pd,
	}, true, nil)

	txManager.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).AnyTimes().Return(nil)

	profileService.EXPECT().GetProfile(profileID, profileVersion).AnyTimes().Return(&profileapi.Verifier{
		ID:      profileID,
		Version: profileVersion,
		Active:  true,
		Checks: &profileapi.VerificationChecks{
			Presentation: &profileapi.PresentationChecks{
				VCSubject: true,
				Format: []vcsverifiable.Format{
					vcsverifiable.Jwt,
				},
			},
			Policy: profileapi.PolicyCheck{
				PolicyURL: presentationPolicyURL,
			},
		},
	}, nil)

	presentationVerifier.EXPECT().VerifyPresentation(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(nil, nil, nil)

	trustRegistry.EXPECT().ValidatePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(nil)

	t.Run("Success without custom claims", func(t *testing.T) {
		txManager2 := NewMockTransactionManager(gomock.NewController(t))

		txManager2.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: pd,
		}, true, nil)

		txManager2.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).Times(1).
			DoAndReturn(func(txID oidc4vp.TxID, claims *oidc4vp.ReceivedClaims) error {
				require.Nil(t, claims.CustomScopeClaims)

				return nil
			})

		s2 := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager2,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
			VDR:                  vdr,
			TrustRegistryService: trustRegistry,
		})

		err = s2.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   issuer,
					VpTokenFormat: vcsverifiable.Jwt,
				}},
			},
		)

		require.NoError(t, err)
	})

	t.Run("Success - two VP tokens (merged) with custom claims and attestation vp", func(t *testing.T) {
		var descriptors []*presexch.InputDescriptor
		err = json.Unmarshal([]byte(twoInputDescriptors), &descriptors)
		require.NoError(t, err)

		defs := &presexch.PresentationDefinition{
			InputDescriptors: descriptors,
		}

		mergedPS := &presexch.PresentationSubmission{
			DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   defs.InputDescriptors[0].ID,
					Path: "$[0]",
					PathNested: &presexch.InputDescriptorMapping{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					},
				},
				{
					ID:   defs.InputDescriptors[1].ID,
					Path: "$[1]",
					PathNested: &presexch.InputDescriptorMapping{
						ID:   defs.InputDescriptors[1].ID,
						Path: "$.verifiableCredential[0]",
					},
				},
			},
		}

		testLoader := testutil.DocumentLoader(t)

		vp1, issuer1, vdr1 := newVPWithPS(t, w, mergedPS, "PhDDegree")
		vp2, issuer2, vdr2 := newVPWithPS(t, w, mergedPS, "BachelorDegree")

		combinedDIDResolver := &vdrmock.VDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				switch didID {
				case issuer1:
					return vdr1.Resolve(didID, opts...)
				case issuer2:
					return vdr2.Resolve(didID, opts...)
				}

				return nil, fmt.Errorf("unexpected issuer")
			}}

		txManager2 := NewMockTransactionManager(gomock.NewController(t))

		s2 := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager2,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       testLoader,
			VDR:                  combinedDIDResolver,
			TrustRegistryService: trustRegistry,
		})

		txManager2.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: defs,
			CustomScopes:           []string{customScope},
		}, true, nil)

		txManager2.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).Times(1).
			DoAndReturn(func(txID oidc4vp.TxID, claims *oidc4vp.ReceivedClaims) error {
				require.Equal(t, map[string]oidc4vp.Claims{
					customScope: {
						"key1": "value1",
					},
				}, claims.CustomScopeClaims)

				return nil
			})

		err = s2.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: map[string]oidc4vp.Claims{
					customScope: {
						"key1": "value1",
					},
				},
				AttestationVP: "attestation_vp.jwt",
				VPTokens: []*oidc4vp.ProcessedVPToken{
					{
						Nonce:         "nonce1",
						Presentation:  vp1,
						SignerDIDID:   issuer1,
						VpTokenFormat: vcsverifiable.Jwt,
					},
					{
						Nonce:         "nonce1",
						Presentation:  vp2,
						SignerDIDID:   issuer2,
						VpTokenFormat: vcsverifiable.Jwt,
					},
				},
			},
		)

		require.NoError(t, err)
	})

	t.Run("Unsupported vp token format", func(t *testing.T) {
		err = s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   issuer,
					VpTokenFormat: vcsverifiable.Ldp,
				}},
			},
		)

		require.ErrorContains(t, err, "profile does not support ldp vp_token format")
	})

	t.Run("Error - Two VP tokens without presentation ID", func(t *testing.T) {
		var descriptors []*presexch.InputDescriptor
		err = json.Unmarshal([]byte(twoInputDescriptors), &descriptors)
		require.NoError(t, err)

		defs := &presexch.PresentationDefinition{
			InputDescriptors: descriptors,
		}

		mergedPS := &presexch.PresentationSubmission{
			DescriptorMap: []*presexch.InputDescriptorMapping{
				{
					ID:   defs.InputDescriptors[0].ID,
					Path: "$[0]",
					PathNested: &presexch.InputDescriptorMapping{
						ID:   defs.InputDescriptors[0].ID,
						Path: "$.verifiableCredential[0]",
					},
				},
				{
					ID:   defs.InputDescriptors[1].ID,
					Path: "$[1]",
					PathNested: &presexch.InputDescriptorMapping{
						ID:   defs.InputDescriptors[1].ID,
						Path: "$.verifiableCredential[0]",
					},
				},
			},
		}

		testLoader := testutil.DocumentLoader(t)

		vp1, issuer1, vdr1 := newVPWithPS(t, w, mergedPS, "PhDDegree")
		vp2, issuer2, vdr2 := newVPWithPS(t, w, mergedPS, "BachelorDegree")

		combinedDIDResolver := &vdrmock.VDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				switch didID {
				case issuer1:
					return vdr1.Resolve(didID, opts...)
				case issuer2:
					return vdr2.Resolve(didID, opts...)
				}

				return nil, fmt.Errorf("unexpected issuer")
			}}

		txManager2 := NewMockTransactionManager(gomock.NewController(t))

		s2 := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager2,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       testLoader,
			VDR:                  combinedDIDResolver,
			TrustRegistryService: trustRegistry,
		})

		txManager2.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: defs,
		}, true, nil)

		txManager2.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).AnyTimes().Return(nil)

		vp1.ID = ""
		vp2.ID = ""

		err = s2.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{
					{
						Nonce:         "nonce1",
						Presentation:  vp1,
						SignerDIDID:   issuer1,
						VpTokenFormat: vcsverifiable.Jwt,
					},
					{
						Nonce:         "nonce1",
						Presentation:  vp2,
						SignerDIDID:   issuer2,
						VpTokenFormat: vcsverifiable.Jwt,
					},
				},
			},
		)

		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate presentation ID: ")
	})

	t.Run("Must have at least one token", func(t *testing.T) {
		err = s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens:          []*oidc4vp.ProcessedVPToken{},
			},
		)

		require.Error(t, err)
		require.Contains(t, err.Error(), "must have at least one token")
	})

	t.Run("VC subject is not much with vp signer", func(t *testing.T) {
		err = s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   "did:example1:ebfeb1f712ebc6f1c276e12ec21",
					VpTokenFormat: vcsverifiable.Jwt,
				}}})

		require.Contains(t, err.Error(), "does not match with vp signer")
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
		errTxManager := NewMockTransactionManager(gomock.NewController(t))
		errTxManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().
			Return(nil, false, errors.New("invalid nonce1"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   errTxManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
		})

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:        "nonce1",
					Presentation: vp,
					SignerDIDID:  "did:example123:ebfeb1f712ebc6f1c276e12ec21",
				}}})

		require.Contains(t, err.Error(), "invalid nonce1")
	})

	t.Run("Invalid Nonce 2", func(t *testing.T) {
		err = s.VerifyOIDCVerifiablePresentation(context.Background(), "txID2",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:        "nonce1",
					Presentation: vp,
					SignerDIDID:  "did:example123:ebfeb1f712ebc6f1c276e12ec21",
				}}})

		require.Contains(t, err.Error(), "invalid nonce")
	})

	t.Run("Invalid _scope (invalid amount)", func(t *testing.T) {
		errTxManager := NewMockTransactionManager(gomock.NewController(t))
		withError := oidc4vp.NewService(&oidc4vp.Config{
			TransactionManager: errTxManager,
		})

		errTxManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: pd,
			CustomScopes:           []string{customScope},
		}, true, nil)

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce: "nonce1",
				}}})

		require.Contains(t, err.Error(), "invalid _scope")
	})

	t.Run("Invalid _scope 2 (no claims supplied)", func(t *testing.T) {
		errTxManager := NewMockTransactionManager(gomock.NewController(t))
		withError := oidc4vp.NewService(&oidc4vp.Config{
			TransactionManager: errTxManager,
		})

		errTxManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: pd,
			CustomScopes:           []string{customScope},
		}, true, nil)

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: map[string]oidc4vp.Claims{
					"customScope2": {},
				},
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce: "nonce1",
				}}})

		require.Contains(t, err.Error(), "invalid _scope")
	})

	t.Run("Invalid _scope 3", func(t *testing.T) {
		err = s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: map[string]oidc4vp.Claims{
					customScope: {},
				},
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce: "nonce1",
				}}})

		require.Contains(t, err.Error(), "invalid _scope")
	})

	t.Run("Get profile error", func(t *testing.T) {
		errProfileService := NewMockProfileService(gomock.NewController(t))
		errProfileService.EXPECT().GetProfile(profileID, profileVersion).Times(1).Return(nil,
			errors.New("get profile error"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       errProfileService,
			DocumentLoader:       loader,
		})

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:        "nonce1",
					Presentation: vp,
					SignerDIDID:  "did:example123:ebfeb1f712ebc6f1c276e12ec21",
				}}})

		require.Contains(t, err.Error(), "get profile error")
	})

	t.Run("verification failed", func(t *testing.T) {
		errPresentationVerifier := NewMockPresentationVerifier(gomock.NewController(t))
		errPresentationVerifier.EXPECT().VerifyPresentation(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
			Return(nil, nil, errors.New("verification failed"))
		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager,
			PresentationVerifier: errPresentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
			VDR:                  vdr,
			TrustRegistryService: trustRegistry,
		})

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   "did:example123:ebfeb1f712ebc6f1c276e12ec21",
					VpTokenFormat: vcsverifiable.Jwt,
				}}})

		require.Contains(t, err.Error(), "verification failed")
	})

	t.Run("Match failed", func(t *testing.T) {
		err = s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  &verifiable.Presentation{},
					VpTokenFormat: vcsverifiable.Jwt,
				}}})
		require.Contains(t, err.Error(), "match:")
	})

	t.Run("Store error", func(t *testing.T) {
		errTxManager := NewMockTransactionManager(gomock.NewController(t))
		errTxManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: pd,
		}, true, nil)

		errTxManager.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).
			Return(errors.New("store error"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   errTxManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
			VDR:                  vdr,
			TrustRegistryService: trustRegistry,
		})

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   issuer,
					VpTokenFormat: vcsverifiable.Jwt,
				}}})

		require.Contains(t, err.Error(), "store error")
	})

	t.Run("Trust Registry error", func(t *testing.T) {
		errTrustRegistry := NewMockTrustRegistryService(gomock.NewController(t))
		errTrustRegistry.EXPECT().ValidatePresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			AnyTimes().Return(errors.New("validate error"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
			VDR:                  vdr,
			TrustRegistryService: errTrustRegistry,
		})

		err = withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   "did:example123:ebfeb1f712ebc6f1c276e12ec21",
					VpTokenFormat: vcsverifiable.Jwt,
				}}})

		require.Contains(t, err.Error(), "check policy")
	})

	t.Run("Event publish error", func(t *testing.T) {
		txManager2 := NewMockTransactionManager(gomock.NewController(t))

		txManager2.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: pd,
		}, true, nil)

		txManager2.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).Times(1)

		errExpected := errors.New("injected publish error")

		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Times(2).
			DoAndReturn(
				func(ctx context.Context, topic string, messages ...*spi.Event) error {
					require.Len(t, messages, 1)

					switch messages[0].Type { //nolint:exhaustive
					case spi.VerifierOIDCInteractionQRScanned:
						return nil
					case spi.VerifierOIDCInteractionSucceeded:
						return errExpected
					default:
						return fmt.Errorf("unexpected event type: %s", messages[0].Type)
					}
				},
			)

		s2 := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             mockEventSvc,
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager2,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
			VDR:                  vdr,
			TrustRegistryService: trustRegistry,
		})

		err = s2.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			&oidc4vp.AuthorizationResponseParsed{
				CustomScopeClaims: nil,
				VPTokens: []*oidc4vp.ProcessedVPToken{{
					Nonce:         "nonce1",
					Presentation:  vp,
					SignerDIDID:   issuer,
					VpTokenFormat: vcsverifiable.Jwt,
				}},
			},
		)

		require.ErrorContains(t, err, errExpected.Error())
	})
}

func TestService_GetTx(t *testing.T) {
	txManager := NewMockTransactionManager(gomock.NewController(t))
	txManager.EXPECT().Get(oidc4vp.TxID("test")).Times(1).Return(&oidc4vp.Transaction{
		ProfileID: "testP1",
	}, nil)

	svc := oidc4vp.NewService(&oidc4vp.Config{
		TransactionManager: txManager,
	})

	t.Run("Success", func(t *testing.T) {
		tx, err := svc.GetTx(context.Background(), "test")
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "testP1", tx.ProfileID)
	})
}

func TestService_DeleteClaims(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		txManager := NewMockTransactionManager(gomock.NewController(t))
		txManager.EXPECT().DeleteReceivedClaims("claimsID").Times(1).Return(nil)

		svc := oidc4vp.NewService(&oidc4vp.Config{
			TransactionManager: txManager,
		})

		err := svc.DeleteClaims(context.Background(), "claimsID")
		require.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		txManager := NewMockTransactionManager(gomock.NewController(t))
		txManager.EXPECT().DeleteReceivedClaims("claimsID").Times(1).Return(fmt.Errorf("delete error"))

		svc := oidc4vp.NewService(&oidc4vp.Config{
			TransactionManager: txManager,
		})

		err := svc.DeleteClaims(context.Background(), "claimsID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "delete error")
	})
}

func TestService_RetrieveClaims(t *testing.T) {
	loader := testutil.DocumentLoader(t)

	t.Run("Success JWT with custom claims", func(t *testing.T) {
		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).DoAndReturn(
			expectedPublishEventFunc(t, spi.VerifierOIDCInteractionClaimsRetrieved, nil),
		)

		svc := oidc4vp.NewService(&oidc4vp.Config{EventSvc: mockEventSvc, EventTopic: spi.VerifierEventTopic})

		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(loader),
			verifiable.WithDisabledProofCheck())

		require.NoError(t, err)

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{
				Credentials: map[string]*verifiable.Credential{
					"id": jwtvc,
				},
				CustomScopeClaims: map[string]oidc4vp.Claims{
					customScope: {
						"key1": "value1",
					},
				},
			},
		}, &profileapi.Verifier{})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]map[string]interface{})

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0]["id"])

		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].Issuer)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].IssuanceDate)
		require.Empty(t, claims["http://example.gov/credentials/3732"].ExpirationDate)
		require.Equal(t,
			oidc4vp.CredentialMetadata{CustomClaims: map[string]oidc4vp.Claims{customScope: {"key1": "value1"}}},
			claims["_scope"],
		)
	})

	t.Run("Success JsonLD without custom claims", func(t *testing.T) {
		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).DoAndReturn(
			expectedPublishEventFunc(t, spi.VerifierOIDCInteractionClaimsRetrieved, nil),
		)

		svc := oidc4vp.NewService(&oidc4vp.Config{EventSvc: mockEventSvc, EventTopic: spi.VerifierEventTopic})
		ldvc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(loader),
			verifiable.WithDisabledProofCheck())

		require.NoError(t, err)

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": ldvc,
			}}}, &profileapi.Verifier{})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]map[string]interface{})

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0]["id"])

		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].Issuer)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].IssuanceDate)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].ExpirationDate)
		require.Empty(t, claims["_scope"])
	})

	t.Run("Empty claims", func(t *testing.T) {
		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).DoAndReturn(
			expectedPublishEventFunc(t, spi.VerifierOIDCInteractionClaimsRetrieved, nil),
		)

		svc := oidc4vp.NewService(&oidc4vp.Config{EventSvc: mockEventSvc, EventTopic: spi.VerifierEventTopic})
		credential, err := verifiable.CreateCredential(verifiable.CredentialContents{
			SDJWTHashAlg: lo.ToPtr(crypto.SHA384),
		}, nil)
		require.NoError(t, err)

		credential.JWTEnvelope = &verifiable.JWTEnvelope{
			JWT: "abc",
		}

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": credential,
			}}}, &profileapi.Verifier{})

		require.Empty(t, claims)
	})

	t.Run("Success with publish event error", func(t *testing.T) {
		mockEventSvc := NewMockeventService(gomock.NewController(t))
		mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).DoAndReturn(
			expectedPublishEventFunc(t, spi.VerifierOIDCInteractionClaimsRetrieved, errors.New("injected publish error")),
		)

		svc := oidc4vp.NewService(&oidc4vp.Config{EventSvc: mockEventSvc, EventTopic: spi.VerifierEventTopic})

		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(loader),
			verifiable.WithDisabledProofCheck())

		require.NoError(t, err)

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{
				Credentials: map[string]*verifiable.Credential{
					"id": jwtvc,
				},
				CustomScopeClaims: map[string]oidc4vp.Claims{
					customScope: {
						"key1": "value1",
					},
				},
			},
		}, &profileapi.Verifier{})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]map[string]interface{})

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0]["id"])

		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].Issuer)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].IssuanceDate)
		require.Empty(t, claims["http://example.gov/credentials/3732"].ExpirationDate)
		require.Equal(t,
			oidc4vp.CredentialMetadata{CustomClaims: map[string]oidc4vp.Claims{customScope: {"key1": "value1"}}},
			claims["_scope"],
		)
	})
}

func createCryptoSuite(t *testing.T) api.Suite {
	t.Helper()

	p, err := arieskms.NewAriesProviderWrapper(ariesmockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	cryptoSuite, err := localsuite.NewLocalCryptoSuite("local-lock://custom/primary/key/", p, &noop.NoLock{})
	require.NoError(t, err)

	return cryptoSuite
}

type mockEvent struct {
	err error
}

func (m *mockEvent) Publish(_ context.Context, _ string, _ ...*spi.Event) error {
	if m.err != nil {
		return m.err
	}

	return nil
}

func newVPWithPD(t *testing.T, keyCreatorSigner wrapperCreatorSigner) (
	*verifiable.Presentation, *presexch.PresentationDefinition, string,
	vdrapi.Registry, *lddocloader.DocumentLoader) {
	uri := randomURI()

	customType := "CustomType"

	expected, issuer, pubKeyFetcher := newSignedJWTVC(t, keyCreatorSigner, []string{uri}, "", "", []string{customType})

	defs := &presexch.PresentationDefinition{
		InputDescriptors: []*presexch.InputDescriptor{{
			ID: uuid.New().String(),
			Schema: []*presexch.Schema{{
				URI: fmt.Sprintf("%s#%s", uri, customType),
			}},
		}},
	}

	docLoader := createTestDocumentLoader(t, uri, customType)

	return newVP(t,
		&presexch.PresentationSubmission{DescriptorMap: []*presexch.InputDescriptorMapping{{
			ID:   defs.InputDescriptors[0].ID,
			Path: "$.verifiableCredential[0]",
		}}},
		expected,
	), defs, issuer, pubKeyFetcher, docLoader
}

func newVPWithPS(t *testing.T, keyCreatorSigner wrapperCreatorSigner,
	ps *presexch.PresentationSubmission, value string) (
	*verifiable.Presentation, string, vdrapi.Registry) {
	expected, issuer, pubKeyFetcher := newSignedJWTVC(t, keyCreatorSigner, nil,
		"degree", value, []string{})

	return newVP(t, ps,
		expected,
	), issuer, pubKeyFetcher
}

func newVP(t *testing.T, submission *presexch.PresentationSubmission,
	vcs ...*verifiable.Credential) *verifiable.Presentation {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs...))
	vp.ID = uuid.New().String() // TODO: Can we rely on this for code
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://identity.foundation/presentation-exchange/submission/v1")
	vp.Type = append(vp.Type, "PresentationSubmission")

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toMap(t, submission)
	}

	return vp
}

func newVC(issuer string, ctx []string, customTypes []string) verifiable.CredentialContents {
	cred := verifiable.CredentialContents{
		Context: []string{verifiable.ContextURI},
		Types:   append([]string{verifiable.VCType}, customTypes...),
		ID:      "http://test.credential.com/123",
		Issuer:  &verifiable.Issuer{ID: issuer},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Expired: &util.TimeWrapper{
			Time: time.Now().AddDate(1, 0, 0),
		},
		Subject: []verifiable.Subject{{
			ID: issuer,
		}},
	}

	if ctx != nil {
		cred.Context = append(cred.Context, ctx...)
	}

	return cred
}

func newDegreeVC(issuer string, degreeType string, ctx []string, customTypes []string) verifiable.CredentialContents {
	cred := verifiable.CredentialContents{
		Context: []string{verifiable.ContextURI},
		Types:   append([]string{verifiable.VCType}, customTypes...),
		ID:      uuid.New().String(),
		Issuer:  &verifiable.Issuer{ID: issuer},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Expired: &util.TimeWrapper{
			Time: time.Now().AddDate(1, 0, 0),
		},
		Subject: []verifiable.Subject{{
			ID: issuer,
			CustomFields: map[string]interface{}{
				"degree": map[string]interface{}{
					"type":   degreeType,
					"degree": "MIT",
				},
			}}},
	}

	if ctx != nil {
		cred.Context = append(cred.Context, ctx...)
	}

	return cred
}

type wrapperCreatorSigner interface {
	api.KeyCreator
	api.KMSCryptoSigner
}

func newSignedJWTVC(t *testing.T,
	keyCreatorSigner wrapperCreatorSigner, ctx []string,
	vcType string, value string, customTypes []string) (*verifiable.Credential, string, vdrapi.Registry) {
	t.Helper()

	pub, err := keyCreatorSigner.Create(kms.ED25519Type)
	require.NoError(t, err)

	fks, err := keyCreatorSigner.FixedKeySigner(pub)
	require.NoError(t, err)

	signer := testsupport.NewProofCreator(fks)

	issuer, verMethod, err := fingerprint.CreateDIDKeyByJwk(pub)
	require.NoError(t, err)

	verificationMethod, err := did.NewVerificationMethodFromJWK(verMethod, "JsonWebKey2020", issuer, pub)
	require.NoError(t, err)

	didResolver := &vdrmock.VDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			return makeMockDIDResolution(issuer, verificationMethod, did.Authentication), nil
		}}

	var vcc verifiable.CredentialContents

	switch vcType {
	case "degree":
		vcc = newDegreeVC(issuer, value, ctx, customTypes)
	default:
		vcc = newVC(issuer, ctx, customTypes)
	}

	vc, err := verifiable.CreateCredential(vcc, nil)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	vc, err = vc.CreateSignedJWTVC(false, jwsAlgo, signer, verMethod)
	require.NoError(t, err)

	return vc, issuer, didResolver
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

func randomURI() string {
	return fmt.Sprintf("https://my.test.context.jsonld/%s", uuid.New().String())
}

func createTestDocumentLoader(t *testing.T, contextURL string, types ...string) *lddocloader.DocumentLoader {
	include := fmt.Sprintf(`"ctx":"%s#"`, contextURL)

	for _, typ := range types {
		include += fmt.Sprintf(`,"%s":"ctx:%s"`, typ, typ)
	}

	jsonLDContext := fmt.Sprintf(`{
    "@context":{
      "@version":1.1,
      "@protected":true,
      "name":"http://schema.org/name",
      "ex":"https://example.org/examples#",
      "xsd":"http://www.w3.org/2001/XMLSchema#",
	  %s
	   }
	}`, include)

	loader := testutil.DocumentLoader(t, ldcontext.Document{
		URL:     contextURL,
		Content: []byte(jsonLDContext),
	})

	return loader
}

func toMap(t *testing.T, v interface{}) map[string]interface{} {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	m := make(map[string]interface{})

	err = json.Unmarshal(bits, &m)
	require.NoError(t, err)

	return m
}

const twoInputDescriptors = `
[
  {
    "id": "phd-degree",
    "name": "phd-degree",
    "purpose": "We can only hire with PhD degree.",
    "schema": [
      {
        "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
      }
    ],
    "constraints": {
      "fields": [
        {
          "path": [
            "$.credentialSubject.degree.type",
            "$.vc.credentialSubject.degree.type"
          ],
          "purpose": "We can only hire with PhD degree.",
          "filter": {
            "type": "string",
            "const": "PhDDegree"
          }
        }
      ]
    }
  },
  {
    "id": "bachelor-degree",
    "name": "bachelor-degree",
    "purpose": "We can only hire with bachelor degree.",
    "schema": [
      {
        "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
      }
    ],
    "constraints": {
      "fields": [
        {
          "path": [
            "$.credentialSubject.degree.type",
            "$.vc.credentialSubject.degree.type"
          ],
          "purpose": "We can only hire with bachelor degree.",
          "filter": {
            "type": "string",
            "const": "BachelorDegree"
          }
        }
      ]
    }
  }
]`

func Test_GetSupportedVPFormats(t *testing.T) {
	type args struct {
		kmsSupportedKeyTypes []kms.KeyType
		supportedVPFormats   []vcsverifiable.Format
		supportedVCFormats   []vcsverifiable.Format
	}
	tests := []struct {
		name string
		args args
		want *presexch.Format
	}{
		{
			name: "OK with duplications",
			args: args{
				kmsSupportedKeyTypes: []kms.KeyType{
					kms.ED25519Type,
					kms.ECDSAP256TypeDER,
				},
				supportedVPFormats: []vcsverifiable.Format{
					vcsverifiable.Jwt,
					vcsverifiable.Ldp,
				},
				supportedVCFormats: []vcsverifiable.Format{
					vcsverifiable.Jwt,
					vcsverifiable.Ldp,
				},
			},
			want: &presexch.Format{
				JwtVC: &presexch.JwtType{Alg: []string{
					"EdDSA",
					"ES256",
				}},
				JwtVP: &presexch.JwtType{Alg: []string{
					"EdDSA",
					"ES256",
				}},
				LdpVC: &presexch.LdpType{ProofType: []string{
					"Ed25519Signature2018",
					"Ed25519Signature2020",
					"JsonWebSignature2020",
				}},
				LdpVP: &presexch.LdpType{ProofType: []string{
					"Ed25519Signature2018",
					"Ed25519Signature2020",
					"JsonWebSignature2020",
				}},
			},
		},
		{
			name: "OK",
			args: args{
				kmsSupportedKeyTypes: []kms.KeyType{
					kms.ED25519Type,
					kms.ECDSAP256TypeDER,
				},
				supportedVPFormats: []vcsverifiable.Format{
					vcsverifiable.Jwt,
				},
				supportedVCFormats: []vcsverifiable.Format{
					vcsverifiable.Ldp,
				},
			},
			want: &presexch.Format{
				JwtVC: nil,
				JwtVP: &presexch.JwtType{Alg: []string{
					"EdDSA",
					"ES256",
				}},
				LdpVC: &presexch.LdpType{ProofType: []string{
					"Ed25519Signature2018",
					"Ed25519Signature2020",
					"JsonWebSignature2020",
				}},
				LdpVP: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oidc4vp.GetSupportedVPFormats(
				tt.args.kmsSupportedKeyTypes, tt.args.supportedVPFormats, tt.args.supportedVCFormats)

			assert.Equal(t, tt.want.JwtVC == nil, got.JwtVC == nil)
			if got.JwtVC != nil {
				assert.ElementsMatch(t, tt.want.JwtVC.Alg, got.JwtVC.Alg)
			}

			assert.Equal(t, tt.want.JwtVP == nil, got.JwtVP == nil)
			if got.JwtVC != nil {
				assert.ElementsMatch(t, tt.want.JwtVP.Alg, got.JwtVP.Alg)
			}

			assert.Equal(t, tt.want.LdpVC == nil, got.LdpVC == nil)
			if got.JwtVC != nil {
				assert.ElementsMatch(t, tt.want.LdpVC.ProofType, got.LdpVC.ProofType)
			}

			assert.Equal(t, tt.want.LdpVP == nil, got.LdpVP == nil)
			if got.JwtVC != nil {
				assert.ElementsMatch(t, tt.want.LdpVP.ProofType, got.LdpVP.ProofType)
			}
		})
	}
}

type eventPublishFunc func(ctx context.Context, topic string, messages ...*spi.Event) error

func expectedPublishEventFunc(t *testing.T, eventType spi.EventType, err error) eventPublishFunc { //nolint:unparam
	t.Helper()

	return func(ctx context.Context, topic string, messages ...*spi.Event) error {
		require.Len(t, messages, 1)
		require.Equal(t, eventType, messages[0].Type)

		return err
	}
}
