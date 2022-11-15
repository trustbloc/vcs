/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestExchangeCode(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	oauth2Client := NewMockOAuth2Client(gomock.NewController(t))

	srv, err := oidc4ci.NewService(&oidc4ci.Config{TransactionStore: store, OAuth2Client: oauth2Client,
		HTTPClient: &http.Client{}})
	assert.NoError(t, err)

	opState := uuid.NewString()
	authCode := uuid.NewString()

	baseTx := &oidc4ci.Transaction{
		ID: oidc4ci.TxID("id"),
		TransactionData: oidc4ci.TransactionData{
			TokenEndpoint:  "https://localhost/token",
			IssuerAuthCode: authCode,
		},
	}

	store.EXPECT().FindByOpState(gomock.Any(), opState).Return(baseTx, nil)
	store.EXPECT().Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx *oidc4ci.Transaction) error {
			assert.Equal(t, baseTx, tx)
			assert.Equal(t, "SlAV32hkKG", tx.IssuerToken)

			return nil
		})

	oauth2Client.EXPECT().Exchange(gomock.Any(), oauth2.Config{
		ClientID:     baseTx.ClientID,
		ClientSecret: baseTx.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   baseTx.AuthorizationEndpoint,
			TokenURL:  baseTx.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		Scopes: baseTx.Scope,
	}, authCode, gomock.Any(), gomock.Any()).Return(&oauth2.Token{
		AccessToken: "SlAV32hkKG",
	}, nil)

	resp, err := srv.ExchangeAuthorizationCode(context.TODO(), opState)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func TestExchangeCodeErrFindTx(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	srv, err := oidc4ci.NewService(&oidc4ci.Config{TransactionStore: store, HTTPClient: &http.Client{}})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(nil, errors.New("tx not found"))
	resp, err := srv.ExchangeAuthorizationCode(context.TODO(), "123")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "tx not found")
}

func TestExchangeCodeIssuerError(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	oauth2Client := NewMockOAuth2Client(gomock.NewController(t))

	srv, err := oidc4ci.NewService(&oidc4ci.Config{TransactionStore: store, OAuth2Client: oauth2Client,
		HTTPClient: &http.Client{}})
	assert.NoError(t, err)

	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4ci.Transaction{
		TransactionData: oidc4ci.TransactionData{
			TokenEndpoint: "https://localhost/token",
		},
	}, nil)

	oauth2Client.EXPECT().Exchange(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		nil,
		errors.New("oauth2: server response missing access_token"),
	)

	resp, err := srv.ExchangeAuthorizationCode(context.TODO(), "sadsadas")
	assert.Empty(t, resp)
	assert.ErrorContains(t, err, "oauth2: server response missing access_token")
}

func TestExchangeCodeStoreUpdateErr(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	oauth2Client := NewMockOAuth2Client(gomock.NewController(t))

	srv, err := oidc4ci.NewService(&oidc4ci.Config{TransactionStore: store, OAuth2Client: oauth2Client,
		HTTPClient: &http.Client{}})
	assert.NoError(t, err)

	opState := uuid.NewString()
	authCode := uuid.NewString()

	baseTx := &oidc4ci.Transaction{
		ID: oidc4ci.TxID("id"),
		TransactionData: oidc4ci.TransactionData{
			TokenEndpoint:  "https://localhost/token",
			IssuerAuthCode: authCode,
		},
	}

	oauth2Client.EXPECT().Exchange(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		&oauth2.Token{
			AccessToken: "1234",
		},
		nil,
	)

	store.EXPECT().FindByOpState(gomock.Any(), opState).Return(baseTx, nil)
	store.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("update error"))

	resp, err := srv.ExchangeAuthorizationCode(context.TODO(), opState)
	assert.ErrorContains(t, err, "update error")
	assert.Empty(t, resp)
}
