/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp_test

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

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

func TestService_InitiateOidcInteraction(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(
		&mockVCSKeyManager{crypto: customCrypto, kms: customKMS}, nil)

	txManager := NewMockTransactionManager(gomock.NewController(t))
	txManager.EXPECT().CreateTx(gomock.Any(), gomock.Any()).AnyTimes().Return(&oidc4vp.Transaction{
		ID:                     "TxID1",
		ProfileID:              "test4",
		PresentationDefinition: &presexch.PresentationDefinition{},
	}, "nonce1", nil)
	requestObjectPublicStore := NewMockRequestObjectPublicStore(gomock.NewController(t))
	requestObjectPublicStore.EXPECT().Publish(gomock.Any(), gomock.Any()).
		AnyTimes().DoAndReturn(func(token string, event *spi.Event) (string, error) {
		return "someurl/abc", nil
	})

	s := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:                 &mockEvent{},
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
			DID:     "did:test:acde",
			Creator: "did:test:acde#" + keyID,
		},
	}

	t.Run("Success", func(t *testing.T) {
		info, err := s.InitiateOidcInteraction(&presexch.PresentationDefinition{
			ID: "test",
		}, "test", correctProfile)

		require.NoError(t, err)
		require.NotNil(t, info)
	})

	t.Run("No signature did", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.SigningDID = nil

		info, err := s.InitiateOidcInteraction(&presexch.PresentationDefinition{}, "test", incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("Tx create failed", func(t *testing.T) {
		txManagerErr := NewMockTransactionManager(gomock.NewController(t))
		txManagerErr.EXPECT().CreateTx(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, "", errors.New("fail"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:                 &mockEvent{},
			TransactionManager:       txManagerErr,
			RequestObjectPublicStore: requestObjectPublicStore,
			KMSRegistry:              kmsRegistry,
			RedirectURL:              "test://redirect",
		})

		info, err := withError.InitiateOidcInteraction(&presexch.PresentationDefinition{}, "test", correctProfile)

		require.Contains(t, err.Error(), "create oidc tx")
		require.Nil(t, info)
	})

	t.Run("publish request object failed", func(t *testing.T) {
		requestObjectPublicStoreErr := NewMockRequestObjectPublicStore(gomock.NewController(t))
		requestObjectPublicStoreErr.EXPECT().Publish(gomock.Any(), gomock.Any()).
			AnyTimes().Return("", errors.New("fail"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:                 &mockEvent{},
			TransactionManager:       txManager,
			RequestObjectPublicStore: requestObjectPublicStoreErr,
			KMSRegistry:              kmsRegistry,
			RedirectURL:              "test://redirect",
		})

		info, err := withError.InitiateOidcInteraction(&presexch.PresentationDefinition{}, "test", correctProfile)

		require.Contains(t, err.Error(), "publish request object")
		require.Nil(t, info)
	})

	t.Run("fail to get kms form registry", func(t *testing.T) {
		kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
		kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil, errors.New("fail"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:                 &mockEvent{},
			TransactionManager:       txManager,
			RequestObjectPublicStore: requestObjectPublicStore,
			KMSRegistry:              kmsRegistry,
			RedirectURL:              "test://redirect",
		})

		info, err := withError.InitiateOidcInteraction(&presexch.PresentationDefinition{}, "test", correctProfile)

		require.Contains(t, err.Error(), "get key manager")
		require.Nil(t, info)
	})

	t.Run("Invalid key", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.SigningDID.Creator = "invalid"

		info, err := s.InitiateOidcInteraction(&presexch.PresentationDefinition{}, "test", incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})

	t.Run("Invalid key type", func(t *testing.T) {
		incorrectProfile := &profileapi.Verifier{}
		require.NoError(t, copier.Copy(incorrectProfile, correctProfile))
		incorrectProfile.OIDCConfig.KeyType = "invalid"

		info, err := s.InitiateOidcInteraction(&presexch.PresentationDefinition{}, "test", incorrectProfile)

		require.Error(t, err)
		require.Nil(t, info)
	})
}

func TestService_VerifyOIDCVerifiablePresentation(t *testing.T) {
	txManager := NewMockTransactionManager(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))
	presentationVerifier := NewMockPresentationVerifier(gomock.NewController(t))
	vp, pd, loader := newVPWithPD(t)

	s := oidc4vp.NewService(&oidc4vp.Config{
		EventSvc:             &mockEvent{},
		TransactionManager:   txManager,
		PresentationVerifier: presentationVerifier,
		ProfileService:       profileService,
		DocumentLoader:       loader,
	})

	txManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
		ID:                     "txID1",
		ProfileID:              "testP1",
		PresentationDefinition: pd,
	}, true, nil)

	txManager.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).Return(nil)

	profileService.EXPECT().GetProfile("testP1").AnyTimes().Return(&profileapi.Verifier{
		ID:     "testP1",
		Active: true,
	}, nil)

	presentationVerifier.EXPECT().VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().Return(nil, nil)

	t.Run("Success", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation("txID1", "nonce1", vp)

		require.NoError(t, err)
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
		errTxManager := NewMockTransactionManager(gomock.NewController(t))
		errTxManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().
			Return(nil, false, errors.New("invalid nonce1"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			TransactionManager:   errTxManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
		})

		err := withError.VerifyOIDCVerifiablePresentation("txID1", "nonce1", vp)

		require.Contains(t, err.Error(), "invalid nonce1")
	})

	t.Run("Invalid Nonce 2", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation("txID2", "nonce1", vp)

		require.Contains(t, err.Error(), "invalid nonce")
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
		errProfileService := NewMockProfileService(gomock.NewController(t))
		errProfileService.EXPECT().GetProfile(gomock.Any()).Times(1).Return(nil,
			errors.New("get profile error"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			TransactionManager:   txManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       errProfileService,
			DocumentLoader:       loader,
		})

		err := withError.VerifyOIDCVerifiablePresentation("txID1", "nonce1", vp)

		require.Contains(t, err.Error(), "get profile error")
	})

	t.Run("verification failed", func(t *testing.T) {
		errPresentationVerifier := NewMockPresentationVerifier(gomock.NewController(t))
		errPresentationVerifier.EXPECT().VerifyPresentation(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
			Return(nil, errors.New("verification failed"))
		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			TransactionManager:   txManager,
			PresentationVerifier: errPresentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
		})

		err := withError.VerifyOIDCVerifiablePresentation("txID1", "nonce1", vp)

		require.Contains(t, err.Error(), "verification failed")
	})

	t.Run("Match failed", func(t *testing.T) {
		err := s.VerifyOIDCVerifiablePresentation("txID1", "nonce1", &verifiable.Presentation{})

		require.Contains(t, err.Error(), "match:")
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
		errTxManager := NewMockTransactionManager(gomock.NewController(t))
		errTxManager.EXPECT().GetByOneTimeToken("nonce1").AnyTimes().Return(&oidc4vp.Transaction{
			ID:                     "txID1",
			ProfileID:              "testP1",
			PresentationDefinition: pd,
		}, true, nil)

		errTxManager.EXPECT().StoreReceivedClaims(oidc4vp.TxID("txID1"), gomock.Any()).
			Return(errors.New("store error"))

		withError := oidc4vp.NewService(&oidc4vp.Config{
			EventSvc:             &mockEvent{},
			TransactionManager:   errTxManager,
			PresentationVerifier: presentationVerifier,
			ProfileService:       profileService,
			DocumentLoader:       loader,
		})

		err := withError.VerifyOIDCVerifiablePresentation("txID1", "nonce1", vp)

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
		tx, err := svc.GetTx("test")
		require.NoError(t, err)
		require.NotNil(t, tx)
		require.Equal(t, "testP1", tx.ProfileID)
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

		claims := svc.RetrieveClaims(&oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": jwtvc,
			}}})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]verifiable.Subject)

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0].ID)
	})

	t.Run("Success JsonLD", func(t *testing.T) {
		ldvc, err := verifiable.ParseCredential([]byte(sampleVCJsonLD),
			verifiable.WithJSONLDDocumentLoader(loader),
			verifiable.WithDisabledProofCheck())

		require.NoError(t, err)

		claims := svc.RetrieveClaims(&oidc4vp.Transaction{
			ReceivedClaims: &oidc4vp.ReceivedClaims{Credentials: map[string]*verifiable.Credential{
				"id": ldvc,
			}}})

		require.NotNil(t, claims)
		subjects, ok := claims["http://example.gov/credentials/3732"].SubjectData.([]verifiable.Subject)

		require.True(t, ok)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjects[0].ID)
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
	return signer.NewKMSSigner(m.kms, m.crypto, creator, signatureType)
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

func (m *mockEvent) Publish(topic string, messages ...*spi.Event) error {
	if m.err != nil {
		return m.err
	}

	return nil
}

func newVPWithPD(t *testing.T) (*verifiable.Presentation, *presexch.PresentationDefinition, *ld.DocumentLoader) {
	uri := randomURI()

	customType := "CustomType"

	expected := newVC([]string{uri})
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
	), defs, docLoader
}

func newVP(t *testing.T, submission *presexch.PresentationSubmission,
	vcs ...*verifiable.Credential) *verifiable.Presentation {
	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vcs...))
	require.NoError(t, err)

	vp.Context = append(vp.Context, "https://identity.foundation/presentation-exchange/submission/v1")
	vp.Type = append(vp.Type, "PresentationSubmission")

	if submission != nil {
		vp.CustomFields = make(map[string]interface{})
		vp.CustomFields["presentation_submission"] = toMap(t, submission)
	}

	return vp
}

func newVC(ctx []string) *verifiable.Credential {
	cred := &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		ID:      "http://test.credential.com/123",
		Issuer:  verifiable.Issuer{ID: "http://test.issuer.com"},
		Issued: &util.TimeWrapper{
			Time: time.Now(),
		},
		Subject: map[string]interface{}{
			"id": uuid.New().String(),
		},
	}

	if ctx != nil {
		cred.Context = append(cred.Context, ctx...)
	}

	return cred
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

func toMap(t *testing.T, v interface{}) map[string]interface{} {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	m := make(map[string]interface{})

	err = json.Unmarshal(bits, &m)
	require.NoError(t, err)

	return m
}
