/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oauth_client_test_mocks_test.go -self_package mocks -package oidc4vc_test -source=oauth_client_test.go -mock_names httpRoundTripper=MockHttpRoundTripper

package oidc4vc_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

// nolint
type httpRoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

func TestOAuth2ClientSuccess(t *testing.T) {
	authCode := uuid.NewString()
	factory := oidc4vc.NewOAuth2ClientFactory()

	client := factory.GetClient(oauth2.Config{
		ClientID:     "213125412",
		ClientSecret: "321",
		Endpoint: oauth2.Endpoint{
			TokenURL:  "https://localhost/token",
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
	})

	roundTripper := NewMockHttpRoundTripper(gomock.NewController(t))
	cl := &http.Client{
		Transport: roundTripper,
	}

	roundTripper.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
		assert.NoError(t, request.ParseForm())
		assert.Equal(t, "authorization_code", request.FormValue("grant_type"))
		assert.Equal(t, authCode, request.FormValue("code"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: io.NopCloser(strings.NewReader("{   \"access_token\": \"SlAV32hkKG\",   \"token_type\": \"Bearer\",   \"refresh_token\": \"8xLOxBtZp8\",   \"expires_in\": 3600,   \"id_token\": \"1234\"  }")), //nolint
		}, nil
	})

	tok, err := client.Exchange(context.WithValue(context.TODO(), oauth2.HTTPClient, cl), authCode)
	assert.NoError(t, err)
	assert.NotNil(t, tok)
}

func TestOAuth2ClientIssuerError(t *testing.T) {
	authCode := uuid.NewString()

	roundTripper := NewMockHttpRoundTripper(gomock.NewController(t))
	cl := &http.Client{
		Transport: roundTripper,
	}

	roundTripper.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: io.NopCloser(strings.NewReader("oauth2: server response missing access_token")),
		}, nil
	}).AnyTimes()

	factory := oidc4vc.NewOAuth2ClientFactory()

	client := factory.GetClient(oauth2.Config{
		ClientID:     "213125412",
		ClientSecret: "321",
		Endpoint: oauth2.Endpoint{
			TokenURL:  "https://localhost/token",
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
	})

	tok, err := client.Exchange(context.WithValue(context.TODO(), oauth2.HTTPClient, cl), authCode)
	assert.ErrorContains(t, err, "oauth2: server response missing access_token")
	assert.Nil(t, tok)
}
