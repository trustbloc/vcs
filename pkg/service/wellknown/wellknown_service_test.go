/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wellknown_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/wellknown"
)

func TestWellKnownService(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))
	httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			"{\n \"issuer\": \"https://accounts.google.com\",\n \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\",\n \"device_authorization_endpoint\": \"https://oauth2.googleapis.com/device/code\",\n \"token_endpoint\": \"https://oauth2.googleapis.com/token\",\n \"userinfo_endpoint\": \"https://openidconnect.googleapis.com/v1/userinfo\",\n \"revocation_endpoint\": \"https://oauth2.googleapis.com/revoke\",\n \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\",\n \"response_types_supported\": [\n  \"code\",\n  \"token\",\n  \"id_token\",\n  \"code token\",\n  \"code id_token\",\n  \"token id_token\",\n  \"code token id_token\",\n  \"none\"\n ],\n \"subject_types_supported\": [\n  \"public\"\n ],\n \"id_token_signing_alg_values_supported\": [\n  \"RS256\"\n ],\n \"scopes_supported\": [\n  \"openid\",\n  \"email\",\n  \"profile\"\n ],\n \"token_endpoint_auth_methods_supported\": [\n  \"client_secret_post\",\n  \"client_secret_basic\"\n ],\n \"claims_supported\": [\n  \"aud\",\n  \"email\",\n  \"email_verified\",\n  \"exp\",\n  \"family_name\",\n  \"given_name\",\n  \"iat\",\n  \"iss\",\n  \"locale\",\n  \"name\",\n  \"picture\",\n  \"sub\"\n ],\n \"code_challenge_methods_supported\": [\n  \"plain\",\n  \"S256\"\n ],\n \"grant_types_supported\": [\n  \"authorization_code\",\n  \"refresh_token\",\n  \"urn:ietf:params:oauth:grant-type:device_code\",\n  \"urn:ietf:params:oauth:grant-type:jwt-bearer\"\n ]\n}")), //nolint:lll
	}, nil)

	srv := wellknown.NewService(httpClient)

	resp, err := srv.GetOIDCConfiguration(context.TODO(), "https://any.com")
	assert.NoError(t, err)

	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", resp.AuthorizationEndpoint)
	assert.Equal(t, "https://oauth2.googleapis.com/token", resp.TokenEndpoint)
}

func TestWellKnown404(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))

	httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusNotFound,
	}, nil)

	srv := wellknown.NewService(httpClient)

	resp, err := srv.GetOIDCConfiguration(context.TODO(), "https://any.com")
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "got unexpected status code: 404")
}

func TestWellKnownInvalidJson(t *testing.T) {
	httpClient := NewMockHTTPClient(gomock.NewController(t))

	httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{")),
	}, nil)

	srv := wellknown.NewService(httpClient)

	resp, err := srv.GetOIDCConfiguration(context.TODO(), "https://any.com")
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "unexpected end of JSON input")
}

func TestClientError(t *testing.T) {
	text := "http error"
	httpClient := NewMockHTTPClient(gomock.NewController(t))

	httpClient.EXPECT().Do(gomock.Any()).Return(nil, errors.New(text))

	srv := wellknown.NewService(httpClient)

	resp, err := srv.GetOIDCConfiguration(context.TODO(), "https://any.com")
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, text)
}

func TestClientBodyErr(t *testing.T) {
	text := "http error"
	httpClient := NewMockHTTPClient(gomock.NewController(t))

	httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(iotest.ErrReader(errors.New(text))),
	}, nil)

	srv := wellknown.NewService(httpClient)

	resp, err := srv.GetOIDCConfiguration(context.TODO(), "https://any.com")
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, text)
}
