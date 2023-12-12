/*
Copyright Avast Software. All Rights Reserved.

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

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestExchangeCode(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))

	httpClient := &http.Client{
		Transport: &mockTransport{
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token":"SlAV32hkKG"}`)),
				}, nil
			},
		},
	}

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		ProfileService:   profileService,
		HTTPClient:       httpClient,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	opState := uuid.NewString()
	authCode := uuid.NewString()

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).DoAndReturn(
		func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationCodeExchanged)

			return nil
		},
	)

	baseTx := &oidc4ci.Transaction{
		ID: oidc4ci.TxID("id"),
		TransactionData: oidc4ci.TransactionData{
			TokenEndpoint:  "https://localhost/token",
			IssuerAuthCode: authCode,
			State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
		},
	}

	store.EXPECT().FindByOpState(gomock.Any(), opState).Return(baseTx, nil)
	store.EXPECT().Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
			assert.Equal(t, baseTx, tx)
			assert.Equal(t, "SlAV32hkKG", tx.IssuerToken)
			assert.Equal(t, oidc4ci.TransactionStateIssuerOIDCAuthorizationDone, tx.State)

			return nil
		})

	profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
		Return(&profile.Issuer{
			OIDCConfig: &profile.OIDCConfig{
				ClientID:           "clientID",
				ClientSecretHandle: "clientSecret",
			},
		}, nil)

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), opState, "", "", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func TestExchangeCodeErrFindTx(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	svc, err := oidc4ci.NewService(&oidc4ci.Config{TransactionStore: store, HTTPClient: &http.Client{}})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(nil, errors.New("tx not found"))
	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), "123", "", "", "")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "tx not found")
}

func TestExchangeCodeProfileGetError(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		ProfileService:   profileService,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4ci.Transaction{
		TransactionData: oidc4ci.TransactionData{
			State:         oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
			TokenEndpoint: "https://localhost/token",
		},
	}, nil)

	profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(nil, errors.New("get profile error"))

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
		DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

			return nil
		})

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), "opState", "", "", "")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "get profile error")
}

func TestExchangeCodeAuthenticateClientError(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))
	clientAttestationService := NewMockClientAttestationService(gomock.NewController(t))

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore:         store,
		ProfileService:           profileService,
		ClientAttestationService: clientAttestationService,
		EventService:             eventMock,
		EventTopic:               spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4ci.Transaction{
		TransactionData: oidc4ci.TransactionData{
			State:         oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
			TokenEndpoint: "https://localhost/token",
		},
	}, nil)

	profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profile.Issuer{
		OIDCConfig: &profile.OIDCConfig{
			TokenEndpointAuthMethodsSupported: []string{"attest_jwt_client_auth"},
		},
		Checks: profile.IssuanceChecks{
			ClientAttestationCheck: profile.ClientAttestationCheck{
				PolicyURL: "https://localhost/policy",
			},
		},
	}, nil)

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
		DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

			return nil
		})

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), "opState", "client_id", "attest_jwt_client_auth", "")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "client_assertion is required")
}

func TestExchangeCodeIssuerError(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))

	httpClient := &http.Client{
		Transport: &mockTransport{
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				}, nil
			},
		},
	}

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		ProfileService:   profileService,
		HTTPClient:       httpClient,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4ci.Transaction{
		TransactionData: oidc4ci.TransactionData{
			State:         oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
			TokenEndpoint: "https://localhost/token",
		},
	}, nil)

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
		DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

			return nil
		})

	profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
		Return(&profile.Issuer{
			OIDCConfig: &profile.OIDCConfig{
				ClientID:           "clientID",
				ClientSecretHandle: "clientSecret",
			},
		}, nil)

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), "sadsadas", "", "", "")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "oauth2: server response missing access_token")
}

func TestExchangeCodeStoreUpdateErr(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))

	httpClient := &http.Client{
		Transport: &mockTransport{
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token":"SlAV32hkKG"}`)),
				}, nil
			},
		},
	}

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		ProfileService:   profileService,
		HTTPClient:       httpClient,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	opState := uuid.NewString()
	authCode := uuid.NewString()

	baseTx := &oidc4ci.Transaction{
		ID: oidc4ci.TxID("id"),
		TransactionData: oidc4ci.TransactionData{
			State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
			TokenEndpoint:  "https://localhost/token",
			IssuerAuthCode: authCode,
		},
	}

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
		DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

			return nil
		})

	profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
		Return(&profile.Issuer{
			OIDCConfig: &profile.OIDCConfig{
				ClientID:           "clientID",
				ClientSecretHandle: "clientSecret",
			},
		}, nil)

	store.EXPECT().FindByOpState(gomock.Any(), opState).Return(baseTx, nil)
	store.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), opState, "", "", "")
	assert.ErrorContains(t, err, "update error")
	assert.Empty(t, resp)
}

func TestExchangeCodeInvalidState(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4ci.Transaction{
		TransactionData: oidc4ci.TransactionData{
			State:         oidc4ci.TransactionStateCredentialsIssued,
			TokenEndpoint: "https://localhost/token",
		},
	}, nil)

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
		DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

			return nil
		})

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), "sadsadas", "", "", "")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "unexpected transition from 5 to 4")
}

func TestExchangeCodePublishError(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))

	httpClient := &http.Client{
		Transport: &mockTransport{
			func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token":"SlAV32hkKG"}`)),
				}, nil
			},
		},
	}

	svc, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		ProfileService:   profileService,
		HTTPClient:       httpClient,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	opState := uuid.NewString()
	authCode := uuid.NewString()

	eventMock.EXPECT().Publish(gomock.Any(), spi.IssuerEventTopic, gomock.Any()).
		DoAndReturn(func(ctx context.Context, topic string, messages ...*spi.Event) error {
			assert.Len(t, messages, 1)
			assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationCodeExchanged)

			return errors.New("publish error")
		})

	baseTx := &oidc4ci.Transaction{
		ID: oidc4ci.TxID("id"),
		TransactionData: oidc4ci.TransactionData{
			TokenEndpoint:  "https://localhost/token",
			IssuerAuthCode: authCode,
			State:          oidc4ci.TransactionStateAwaitingIssuerOIDCAuthorization,
		},
	}

	store.EXPECT().FindByOpState(gomock.Any(), opState).Return(baseTx, nil)
	store.EXPECT().Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
			assert.Equal(t, baseTx, tx)
			assert.Equal(t, "SlAV32hkKG", tx.IssuerToken)
			assert.Equal(t, oidc4ci.TransactionStateIssuerOIDCAuthorizationDone, tx.State)

			return nil
		})

	profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
		Return(&profile.Issuer{
			OIDCConfig: &profile.OIDCConfig{
				ClientID:           "clientID",
				ClientSecretHandle: "clientSecret",
			},
		}, nil)

	resp, err := svc.ExchangeAuthorizationCode(context.TODO(), opState, "", "", "")
	assert.ErrorContains(t, err, "publish error")
	assert.Empty(t, resp)
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}
