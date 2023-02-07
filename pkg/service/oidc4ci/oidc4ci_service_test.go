/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestService_PushAuthorizationDetails(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		ad                   *oidc4ci.AuthorizationDetails
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialType: "universitydegreecredential",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "Fail to find transaction by op state",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(
					nil, errors.New("find tx error"))

				ad = &oidc4ci.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "find tx by op state")
			},
		},
		{
			name: "Credential template not configured",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTemplateNotConfigured)
			},
		},
		{
			name: "Credential type not supported",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialType: "NotSupportedCredentialType",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTypeNotSupported)
			},
		},
		{
			name: "Credential format not supported",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				ad = &oidc4ci.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Jwt,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrCredentialFormatNotSupported)
			},
		},
		{
			name: "Fail to update transaction",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

				ad = &oidc4ci.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "update tx")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore: mockTransactionStore,
			})
			require.NoError(t, err)

			err = svc.PushAuthorizationDetails(context.Background(), "opState", ad)
			tt.check(t, err)
		})
	}
}

func TestService_PrepareClaimDataAuthorizationRequest(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		eventMock            = NewMockEventService(gomock.NewController(t))
		req                  *oidc4ci.PrepareClaimDataAuthorizationRequest
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid", "profile", "address"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(2)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationRequestPrepared)

						return nil
					})

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialType: "UniversityDegreeCredential",
						Format:         vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Failed sending event",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid", "profile", "address"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					}).Times(2)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationRequestPrepared)

						return errors.New("publish event")
					})

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialType: "UniversityDegreeCredential",
						Format:         vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "publish event")
				require.Nil(t, resp)
			},
		},
		{
			name: "Response type mismatch",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						State: oidc4ci.TransactionStateIssuanceInitiated,
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						ResponseType: "code",
						Scope:        []string{"openid"},
					},
				}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					ResponseType: "invalid",
					Scope:        []string{"openid"},
					OpState:      "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrResponseTypeMismatch)
			},
		},
		{
			name: "Invalid scope",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						ResponseType: "code",
						Scope:        []string{"openid", "profile"},
						State:        oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					ResponseType: "code",
					Scope:        []string{"openid", "profile", "address"},
					OpState:      "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrInvalidScope)
			},
		},
		{
			name: "Fail to find transaction by op state",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(
					nil, errors.New("find tx error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState: "opState",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "find tx by op state")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to update transaction",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialType: "UniversityDegreeCredential",
						Format:         vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "update tx")
				require.Empty(t, resp)
			},
		},
		{
			name: "invalid sate",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid"},
						State:            oidc4ci.TransactionStateCredentialsIssued,
					},
				}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialType: "UniversityDegreeCredential",
						Format:         vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "unexpected transaction from 5 to 3")
				require.Empty(t, resp)
			},
		},
		{
			name: "store update error",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), "opState").Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "UniversityDegreeCredential",
						},
						CredentialFormat: vcsverifiable.Ldp,
						ResponseType:     "code",
						Scope:            []string{"openid", "profile", "address"},
						State:            oidc4ci.TransactionStateIssuanceInitiated,
					},
				}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization, tx.State)
						return nil
					})

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					Return(errors.New("store update error"))

				req = &oidc4ci.PrepareClaimDataAuthorizationRequest{
					OpState:      "opState",
					ResponseType: "code",
					Scope:        []string{"openid", "profile"},
					AuthorizationDetails: &oidc4ci.AuthorizationDetails{
						CredentialType: "UniversityDegreeCredential",
						Format:         vcsverifiable.Ldp,
					},
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareClaimDataAuthorizationResponse, err error) {
				require.ErrorContains(t, err, "store update error")
				require.Nil(t, resp)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore: mockTransactionStore,
				EventService:     eventMock,
				EventTopic:       spi.IssuerEventTopic,
			})
			require.NoError(t, err)

			resp, err := svc.PrepareClaimDataAuthorizationRequest(context.Background(), req)
			tt.check(t, resp, err)
		})
	}
}

func TestValidatePreAuthCode(t *testing.T) {
	t.Run("success with pin", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		eventService := NewMockEventService(gomock.NewController(t))
		pinGenerator := NewMockPinGenerator(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
			EventService:     eventService,
			EventTopic:       spi.IssuerEventTopic,
			PinGenerator:     pinGenerator,
		})
		assert.NoError(t, err)

		pinGenerator.EXPECT().Validate("567", "567").Return(true)
		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				State:       oidc4ci.TransactionStateIssuanceInitiated,
				PreAuthCode: "1234",
				UserPin:     "567",
			},
		}, nil)

		eventService.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return nil
			})

		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "567")
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("success without pin", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return nil
			})

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "")
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("error with pin during publishing", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		eventMock := NewMockEventService(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
			EventService:     eventMock,
			EventTopic:       spi.IssuerEventTopic,
		})
		assert.NoError(t, err)

		eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionQRScanned)

				return errors.New("unexpected error")
			})

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "")
		assert.ErrorContains(t, err, "unexpected error")
		assert.Nil(t, resp)
	})

	t.Run("invalid pin", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		pinGenerator := NewMockPinGenerator(gomock.NewController(t))

		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
			PinGenerator:     pinGenerator,
		})
		assert.NoError(t, err)

		pinGenerator.EXPECT().Validate("567", "111").Return(false)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode: "1234",
				UserPin:     "567",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "111")
		assert.ErrorContains(t, err, "invalid pin")
		assert.Nil(t, resp)
	})

	t.Run("fail find tx", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(nil, errors.New("not found"))

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "")
		assert.ErrorContains(t, err, "not found")
		assert.Nil(t, resp)
	})

	t.Run("invalid state", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode: "1234",
				UserPin:     "567",
				State:       oidc4ci.TransactionStateCredentialsIssued,
			},
		}, nil)

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "")
		assert.ErrorContains(t, err, "unexpected transaction from 5 to 2")
		assert.Nil(t, resp)
	})

	t.Run("store update error", func(t *testing.T) {
		storeMock := NewMockTransactionStore(gomock.NewController(t))
		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			TransactionStore: storeMock,
		})
		assert.NoError(t, err)

		storeMock.EXPECT().FindByOpState(gomock.Any(), "1234").Return(&oidc4ci.Transaction{
			TransactionData: oidc4ci.TransactionData{
				PreAuthCode: "1234",
				UserPin:     "",
				State:       oidc4ci.TransactionStateIssuanceInitiated,
			},
		}, nil)
		storeMock.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("store update error"))

		resp, err := srv.ValidatePreAuthorizedCodeRequest(context.TODO(), "1234", "")
		assert.ErrorContains(t, err, "store update error")
		assert.Nil(t, resp)
	})
}

func TestService_PrepareCredential(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		mockClaimDataStore   = NewMockClaimDataStore(gomock.NewController(t))
		eventMock            = NewMockEventService(gomock.NewController(t))
		mockHTTPClient       = NewMockHTTPClient(gomock.NewController(t))
		req                  *oidc4ci.PrepareCredential
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`

				mockHTTPClient.EXPECT().Do(gomock.Any()).DoAndReturn(func(
					req *http.Request,
				) (*http.Response, error) {
					assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
					}, nil
				})

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Success LDP",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						CredentialFormat:    vcsverifiable.Ldp,
						CredentialExpiresAt: lo.ToPtr(time.Now().UTC().Add(55 * time.Hour)),
					},
				}, nil)

				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`

				mockHTTPClient.EXPECT().Do(gomock.Any()).DoAndReturn(func(
					req *http.Request,
				) (*http.Response, error) {
					assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
					}, nil
				})

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				assert.Equal(t, time.Now().UTC().Add(55*time.Hour).Truncate(time.Hour*24),
					resp.Credential.(*verifiable.Credential).Expired.Time.Truncate(time.Hour*24))

				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Success pre-authorized flow",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return nil
					})

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				mockClaimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(&oidc4ci.ClaimData{}, nil)

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, resp)
			},
		},
		{
			name: "Failed to get claims for pre-authorized flow",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				eventMock.EXPECT().Publish(gomock.Any(), gomock.Any()).Times(0)
				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).Times(0)

				mockClaimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(nil, errors.New("get error"))

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "get claim data")
				require.Nil(t, resp)
			},
		},
		{
			name: "Failed to send event for pre-authorized flow",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return nil
					})

				mockClaimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(&oidc4ci.ClaimData{}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionSucceeded)

						return errors.New("publish error")
					})

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "publish error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Failed to update tx state",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					ID: "txID",
					TransactionData: oidc4ci.TransactionData{
						IssuerToken: "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{
							Type: "VerifiedEmployee",
						},
						IsPreAuthFlow:    true,
						ClaimDataID:      uuid.NewString(),
						CredentialFormat: vcsverifiable.Jwt,
					},
				}, nil)

				mockTransactionStore.EXPECT().Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
						assert.Equal(t, oidc4ci.TransactionStateCredentialsIssued, tx.State)
						return errors.New("store err")
					})

				mockClaimDataStore.EXPECT().GetAndDelete(gomock.Any(), gomock.Any()).Return(&oidc4ci.ClaimData{}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "store err")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to find transaction by op state",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(
					nil, errors.New("get error"))

				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "get tx")
				require.Nil(t, resp)
			},
		},
		{
			name: "Credential template not configured",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{},
				}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrCredentialTemplateNotConfigured)
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to make request to claim endpoint",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(nil, errors.New("http error"))

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "http error")
				require.Nil(t, resp)
			},
		},
		{
			name: "Claim endpoint returned other than 200 OK status code",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBuffer(nil)),
				}, nil)

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "claim endpoint returned status code")
				require.Nil(t, resp)
			},
		},
		{
			name: "Fail to decode claim data",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer([]byte("invalid"))),
				}, nil)

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorContains(t, err, "decode claim data")
				require.Nil(t, resp)
			},
		},
		{
			name: "Credential format not supported",
			setup: func() {
				mockTransactionStore.EXPECT().Get(gomock.Any(), oidc4ci.TxID("txID")).Return(&oidc4ci.Transaction{
					TransactionData: oidc4ci.TransactionData{
						IssuerToken:        "issuer-access-token",
						CredentialTemplate: &profileapi.CredentialTemplate{},
					},
				}, nil)

				eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
					DoAndReturn(func(topic string, messages ...*spi.Event) error {
						assert.Len(t, messages, 1)
						assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

						return nil
					})

				claimData := `{"surname":"Smith","givenName":"Pat","jobTitle":"Worker"}`

				mockHTTPClient.EXPECT().Do(gomock.Any()).DoAndReturn(func(
					req *http.Request,
				) (*http.Response, error) {
					assert.Contains(t, req.Header.Get("Authorization"), "Bearer issuer-access-token")
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer([]byte(claimData))),
					}, nil
				})

				req = &oidc4ci.PrepareCredential{
					TxID: "txID",
				}
			},
			check: func(t *testing.T, resp *oidc4ci.PrepareCredentialResult, err error) {
				require.ErrorIs(t, err, oidc4ci.ErrCredentialFormatNotSupported)
				require.Nil(t, resp)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4ci.NewService(&oidc4ci.Config{
				TransactionStore: mockTransactionStore,
				ClaimDataStore:   mockClaimDataStore,
				HTTPClient:       mockHTTPClient,
				EventService:     eventMock,
				EventTopic:       spi.IssuerEventTopic,
			})
			require.NoError(t, err)

			resp, err := svc.PrepareCredential(context.Background(), req)
			tt.check(t, resp, err)
		})
	}
}
