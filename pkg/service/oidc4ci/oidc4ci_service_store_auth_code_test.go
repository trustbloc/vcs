/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestStoreAuthCode(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))

	srv, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	t.Run("update not existing opState", func(t *testing.T) {
		opState := uuid.NewString()
		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(nil, errors.New("not found"))

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, "1234", nil)
		assert.Empty(t, resp)
		assert.ErrorContains(t, storeErr, "not found")
	})

	t.Run("publish error", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4ci.Transaction{
			ID: oidc4ci.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4ci.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return errors.New("update error")
			})

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

				return nil
			})

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, code, nil)
		assert.ErrorContains(t, storeErr, "update error")
		assert.NotEqual(t, tx.ID, resp)
	})

	t.Run("update existing", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4ci.Transaction{
			ID: oidc4ci.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4ci.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return nil
			})

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationCodeStored)

				return nil
			})

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, code, nil)
		assert.NoError(t, storeErr)
		assert.Equal(t, tx.ID, resp)
	})

	t.Run("update existing with publish error", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4ci.Transaction{
			ID: oidc4ci.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4ci.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return nil
			})

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationCodeStored)

				return errors.New("publish error")
			})

		eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

				return nil
			})

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, code, nil)
		assert.ErrorContains(t, storeErr, "publish error")
		assert.NotEqual(t, tx.ID, resp)
	})
}

func TestInitiateWalletFlowFromStoreCode(t *testing.T) {
	t.Run("profile not found", func(t *testing.T) {
		store := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: store,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("issuer not found"))
		resp, err := srv.StoreAuthorizationCode(context.TODO(), "random-op-state", "code123",
			&common.WalletInitiatedFlowData{
				OpState:        "random-op-state",
				ProfileId:      "bank_issuer1",
				ProfileVersion: "v111.0",
			},
		)
		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "issuer not found")
	})

	t.Run("error init", func(t *testing.T) {
		store := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: store,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), "v111.0").
			Return(&profileapi.Issuer{
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "some-template",
					},
				},
				Active:     false,
				VCConfig:   &profileapi.VCConfig{},
				SigningDID: &profileapi.SigningDID{},
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
					IssuerWellKnownURL:               "https://awesome.local",
					ClaimsEndpoint:                   "https://awesome.claims.local",
					GrantTypesSupported: []string{
						"authorization_code",
					},
					ScopesSupported: []string{
						"scope1",
						"scope2",
						"scope3",
					},
				},
			}, nil)

		resp, err := srv.StoreAuthorizationCode(context.TODO(), "random-op-state", "code123",
			&common.WalletInitiatedFlowData{
				OpState:        "random-op-state",
				ProfileId:      "bank_issuer1",
				ProfileVersion: "v111.0",
			},
		)
		assert.Empty(t, resp)
		assert.ErrorContains(t, err, "can not initiate issuance for wallet flow. profile not active")
	})
	t.Run("success", func(t *testing.T) {
		store := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))
		wellKnown := NewMockWellKnownService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: store,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
			ProfileService:   profileSvc,
			WellKnownService: wellKnown,
		})
		assert.NoError(t, err)

		profileSvc.EXPECT().GetProfile(profileapi.ID("bank_issuer1"), "v111.0").
			Return(&profileapi.Issuer{
				CredentialTemplates: []*profileapi.CredentialTemplate{
					{
						ID: "some-template",
					},
				},
				Active:     true,
				VCConfig:   &profileapi.VCConfig{},
				SigningDID: &profileapi.SigningDID{},
				OIDCConfig: &profileapi.OIDCConfig{
					WalletInitiatedAuthFlowSupported: true,
					IssuerWellKnownURL:               "https://awesome.local",
					ClaimsEndpoint:                   "https://awesome.claims.local",
					GrantTypesSupported: []string{
						"authorization_code",
					},
					ScopesSupported: []string{
						"scope1",
						"scope2",
						"scope3",
					},
				},
			}, nil)

		store.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&oidc4ci.Transaction{}, nil)
		wellKnown.EXPECT().GetOIDCConfiguration(gomock.Any(), gomock.Any()).
			Return(&oidc4ci.OIDCConfiguration{}, nil)
		eventMock.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		store.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.StoreAuthorizationCode(context.TODO(), "random-op-state", "code123",
			&common.WalletInitiatedFlowData{
				ClaimEndpoint:        "",
				CredentialTemplateId: "",
				OpState:              "random-op-state",
				ProfileId:            "bank_issuer1",
				ProfileVersion:       "v111.0",
				Scopes: lo.ToPtr([]string{
					"scope1",
					"scope2",
					"scope3",
				}),
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})
}
