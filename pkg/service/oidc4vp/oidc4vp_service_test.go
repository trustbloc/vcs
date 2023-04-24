/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"

	"github.com/trustbloc/vcs/pkg/event/spi"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/jinzhu/copier"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/signer"
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
	profileID      = "testProfileID"
	profileVersion = "v1.0"
)

func TestService_InitiateOidcInteraction(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
		&mockVCSKeyManager{crypto: customCrypto, kms: customKMS}, nil)

	txManager := NewMockTransactionManager(gomock.NewController(t))
	txManager.EXPECT().CreateTx(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(&oidc4vp.Transaction{
		ID:                     "TxID1",
		ProfileID:              "test4",
		PresentationDefinition: &presexch.PresentationDefinition{},
	}, "nonce1", nil)
	requestObjectPublicStore := NewMockRequestObjectPublicStore(gomock.NewController(t))
	requestObjectPublicStore.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().DoAndReturn(func(ctx context.Context, token string, event *spi.Event) (string, error) {
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

	keyID, _, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
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
		SigningDID: &profileapi.SigningDID{
			DID:      "did:test:acde",
			Creator:  "did:test:acde#" + keyID,
			KMSKeyID: keyID,
		},
	}

	t.Run("Success", func(t *testing.T) {
		info, err := s.InitiateOidcInteraction(context.TODO(), &presexch.PresentationDefinition{
			ID: "test",
		}, "test", correctProfile)

		require.NoError(t, err)
		require.NotNil(t, info)
	})

	t.Run("No signature did", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.SigningDID = nil

		info, err := s.InitiateOidcInteraction(context.TODO(), &presexch.PresentationDefinition{}, "test", incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("Tx create failed", func(t *testing.T) {
		txManagerErr := NewMockTransactionManager(gomock.NewController(t))
		txManagerErr.EXPECT().CreateTx(
			gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil, "", errors.New("fail"))

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
			correctProfile,
		)

		require.Contains(t, err.Error(), "create oidc tx")
		require.Nil(t, info)
	})

	t.Run("publish request object failed", func(t *testing.T) {
		requestObjectPublicStoreErr := NewMockRequestObjectPublicStore(gomock.NewController(t))
		requestObjectPublicStoreErr.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
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
			correctProfile,
		)

		require.Contains(t, err.Error(), "get key manager")
		require.Nil(t, info)
	})

	t.Run("Invalid key", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.SigningDID.KMSKeyID = "invalid"

		info, err := s.InitiateOidcInteraction(context.TODO(), &presexch.PresentationDefinition{}, "test", incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("Invalid key type", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.OIDCConfig.KeyType = "invalid"

		info, err := s.InitiateOidcInteraction(context.TODO(), &presexch.PresentationDefinition{}, "test", incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})
}

func TestService_VerifyOIDCVerifiablePresentation(t *testing.T) {
	agent := newAgent(t)

	txManager := NewMockTransactionManager(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))
	presentationVerifier := NewMockPresentationVerifier(gomock.NewController(t))
	vp, pd, issuer, pubKeyFetcher, loader := newVPWithPD(t, agent)

	s := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:             &mockEvent{},
		EventTopic:           spi.VerifierEventTopic,
		TransactionManager:   txManager,
		PresentationVerifier: presentationVerifier,
		ProfileService:       profileService,
		DocumentLoader:       loader,
		PublicKeyFetcher:     pubKeyFetcher,
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
			},
		},
	}, nil)

	presentationVerifier.EXPECT().VerifyPresentation(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(nil, nil)

	t.Run("Success", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       issuer,
			}})

		require.NoError(t, err)
	})

	t.Run("Success - two VP tokens (merged)", func(t *testing.T) {
		var descriptors []*presexch.InputDescriptor
		err := json.Unmarshal([]byte(twoInputDescriptors), &descriptors)
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

		vp1, issuer1, pubKeyFetcher1 := newVPWithPS(t, agent, mergedPS, "PhDDegree")
		vp2, issuer2, pubKeyFetcher2 := newVPWithPS(t, agent, mergedPS, "BachelorDegree")

		combinedFetcher := func(issuerID string, keyID string) (*verifier.PublicKey, error) {
			switch issuerID {
			case issuer1:
				return pubKeyFetcher1(issuerID, keyID)

			case issuer2:
				return pubKeyFetcher2(issuerID, keyID)
			}

			return nil, fmt.Errorf("unexpected issuer")
		}

		txManager2 := NewMockTransactionManager(gomock.NewController(t))

		s2 := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager2,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       testLoader,
			PublicKeyFetcher:     combinedFetcher,
		})

		txManager2.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              profileID,
			ProfileVersion:         profileVersion,
			PresentationDefinition: defs,
		}, true, nil)

		txManager2.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).AnyTimes().Return(nil)

		err = s2.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{
				{
					Nonce:        "nonce1",
					Presentation: vp1,
					Signer:       issuer1,
				},
				{
					Nonce:        "nonce1",
					Presentation: vp2,
					Signer:       issuer2,
				},
			})

		require.NoError(t, err)
	})

	t.Run("Error - Two VP tokens without presentation ID", func(t *testing.T) {
		var descriptors []*presexch.InputDescriptor
		err := json.Unmarshal([]byte(twoInputDescriptors), &descriptors)
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

		vp1, issuer1, pubKeyFetcher1 := newVPWithPS(t, agent, mergedPS, "PhDDegree")
		vp2, issuer2, pubKeyFetcher2 := newVPWithPS(t, agent, mergedPS, "BachelorDegree")

		combinedFetcher := func(issuerID string, keyID string) (*verifier.PublicKey, error) {
			switch issuerID {
			case issuer1:
				return pubKeyFetcher1(issuerID, keyID)

			case issuer2:
				return pubKeyFetcher2(issuerID, keyID)
			}

			return nil, fmt.Errorf("unexpected issuer")
		}

		txManager2 := NewMockTransactionManager(gomock.NewController(t))

		s2 := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager2,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       testLoader,
			PublicKeyFetcher:     combinedFetcher,
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
			[]*oidc4vp.ProcessedVPToken{
				{
					Nonce:        "nonce1",
					Presentation: vp1,
					Signer:       issuer1,
				},
				{
					Nonce:        "nonce1",
					Presentation: vp2,
					Signer:       issuer2,
				},
			})

		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate presentation ID: ")
	})

	t.Run("Must have at least one token", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "must have at least one token")
	})

	t.Run("VC subject is not much with vp signer", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       "did:example1:ebfeb1f712ebc6f1c276e12ec21",
			}})

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

		err := withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       "did:example123:ebfeb1f712ebc6f1c276e12ec21",
			}})

		require.Contains(t, err.Error(), "invalid nonce1")
	})

	t.Run("Invalid Nonce 2", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation(context.Background(), "txID2",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       "did:example123:ebfeb1f712ebc6f1c276e12ec21",
			}})

		require.Contains(t, err.Error(), "invalid nonce")
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
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

		err := withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       "did:example123:ebfeb1f712ebc6f1c276e12ec21",
			}})

		require.Contains(t, err.Error(), "get profile error")
	})

	t.Run("verification failed", func(t *testing.T) {
		errPresentationVerifier := NewMockPresentationVerifier(gomock.NewController(t))
		errPresentationVerifier.EXPECT().VerifyPresentation(
			context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
			Return(nil, errors.New("verification failed"))
		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			EventTopic:           spi.VerifierEventTopic,
			TransactionManager:   txManager,
			PresentationVerifier: errPresentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
			PublicKeyFetcher:     pubKeyFetcher,
		})

		err := withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       "did:example123:ebfeb1f712ebc6f1c276e12ec21",
			}})

		require.Contains(t, err.Error(), "verification failed")
	})

	t.Run("Match failed", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: &verifiable.Presentation{},
			}})
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
			PublicKeyFetcher:     pubKeyFetcher,
		})

		err := withError.VerifyOIDCVerifiablePresentation(context.Background(), "txID1",
			[]*oidc4vp.ProcessedVPToken{{
				Nonce:        "nonce1",
				Presentation: vp,
				Signer:       issuer,
			}})

		require.Contains(t, err.Error(), "store error")
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
	svc := oidc4vp.NewService(&oidc4vp.Config{})
	loader := testutil.DocumentLoader(t)

	t.Run("Success JWT", func(t *testing.T) {
		jwtvc, err := verifiable.ParseCredential([]byte(sampleVCJWT),
			verifiable.WithJSONLDDocumentLoader(loader),
			verifiable.WithDisabledProofCheck())

		require.NoError(t, err)

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": jwtvc,
			}}})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]verifiable.Subject)

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0].ID)

		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].Issuer)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].IssuanceDate)
		require.Empty(t, claims["http://example.gov/credentials/3732"].ExpirationDate)
	})

	t.Run("Success JsonLD", func(t *testing.T) {
		ldvc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(loader),
			verifiable.WithDisabledProofCheck())

		require.NoError(t, err)

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": ldvc,
			}}})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]verifiable.Subject)

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0].ID)

		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].Issuer)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].IssuanceDate)
		require.NotEmpty(t, claims["http://example.gov/credentials/3732"].ExpirationDate)
	})

	t.Run("Error", func(t *testing.T) {
		credential := &verifiable.Credential{
			JWT:          "abc",
			SDJWTHashAlg: "sha-256",
		}

		claims := svc.RetrieveClaims(context.Background(), &oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": credential,
			}}})

		require.Empty(t, claims)
	})
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

func (m *mockVCSKeyManager) NewVCSigner(creator string,
	signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	return signer.NewKMSSigner(m.kms, m.crypto, creator, signatureType, nil)
}

func (m *mockVCSKeyManager) SupportedKeyTypes() []kms.KeyType {
	return []kms.KeyType{kms.ED25519Type}
}
func (m *mockVCSKeyManager) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}
func (m *mockVCSKeyManager) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	return "", nil, nil
}

type mockEvent struct {
	err error
}

func (m *mockEvent) Publish(ctx context.Context, topic string, messages ...*spi.Event) error {
	if m.err != nil {
		return m.err
	}

	return nil
}

func newVPWithPD(t *testing.T, agent *ariescontext.Provider) (
	*verifiable.Presentation, *presexch.PresentationDefinition, string, verifiable.PublicKeyFetcher, *ld.DocumentLoader) {
	uri := randomURI()

	customType := "CustomType"

	expected, issuer, pubKeyFetcher := newSignedJWTVC(t, agent, []string{uri}, "", "")
	expected.Types = append(expected.Types, customType)

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

func newVPWithPS(t *testing.T, agent *ariescontext.Provider, ps *presexch.PresentationSubmission, value string) (
	*verifiable.Presentation, string, verifiable.PublicKeyFetcher) {
	expected, issuer, pubKeyFetcher := newSignedJWTVC(t, agent, nil, "degree", value)

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

func newVC(issuer string, ctx []string) *verifiable.Credential {
	cred := &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://test.credential.com/123",
		Issuer:  verifiable.Issuer{ID: issuer},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": issuer,
		},
	}

	if ctx != nil {
		cred.Context = append(cred.Context, ctx...)
	}

	return cred
}

func newDegreeVC(issuer string, degreeType string, ctx []string) *verifiable.Credential {
	cred := &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      uuid.New().String(),
		Issuer:  verifiable.Issuer{ID: issuer},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": issuer,
			"degree": map[string]interface{}{
				"type":   degreeType,
				"degree": "MIT",
			},
		},
	}

	if ctx != nil {
		cred.Context = append(cred.Context, ctx...)
	}

	return cred
}

func newSignedJWTVC(t *testing.T,
	agent *ariescontext.Provider, ctx []string,
	vcType string, value string) (*verifiable.Credential, string, verifiable.PublicKeyFetcher) {
	t.Helper()

	keyID, kh, err := agent.KMS().Create(kms.ED25519Type)
	require.NoError(t, err)

	signer := suite.NewCryptoSigner(agent.Crypto(), kh)

	pubKey, kt, err := agent.KMS().ExportPubKeyBytes(keyID)
	require.NoError(t, err)
	require.Equal(t, kms.ED25519Type, kt)

	pubKeyFetcher := verifiable.SingleKey(pubKey, kms.ED25519)

	issuer, verMethod := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)

	var vc *verifiable.Credential

	switch vcType {
	case "degree":
		vc = newDegreeVC(issuer, value, ctx)
	default:
		vc = newVC(issuer, ctx)
	}

	vc.Issuer = verifiable.Issuer{ID: issuer}

	claims, err := vc.JWTClaims(false)
	require.NoError(t, err)

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(kms.ED25519Type)
	require.NoError(t, err)

	jws, err := claims.MarshalJWS(jwsAlgo, signer, verMethod)
	require.NoError(t, err)

	vc.JWT = jws

	return vc, issuer, pubKeyFetcher
}

func randomURI() string {
	return fmt.Sprintf("https://my.test.context.jsonld/%s", uuid.New().String())
}

func createTestDocumentLoader(t *testing.T, contextURL string, types ...string) *ld.DocumentLoader {
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

func newAgent(t *testing.T) *ariescontext.Provider {
	t.Helper()

	a, err := aries.New(aries.WithStoreProvider(mem.NewProvider()))
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
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
