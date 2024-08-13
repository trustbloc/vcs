/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientidscheme_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/clientidscheme"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestService_Register(t *testing.T) {
	var (
		clientManager  = NewMockClientManager(gomock.NewController(t))
		httpClient     = NewMockHTTPClient(gomock.NewController(t))
		profileService = NewMockProfileService(gomock.NewController(t))
		store          = NewMockTransactionStore(gomock.NewController(t))

		clientURI, issuerState string
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, err error)
	}{
		{
			name: "success",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "issuer-state"

				clientManager.EXPECT().Get(gomock.Any(), clientURI).Return(nil, clientmanager.ErrClientNotFound)

				clientManager.EXPECT().Create(gomock.Any(), "profileID", "profileVersion", gomock.Any()).DoAndReturn(
					func(
						ctx context.Context,
						profileID, profileVersion string,
						data *clientmanager.ClientMetadata,
					) (*oauth2client.Client, error) {
						require.Equal(t, "test-client", data.Name)
						require.Equal(t, "https://example.com/test-client", data.URI)
						require.Equal(t, []string{"https://example.com/cb"}, data.RedirectURIs)
						require.Equal(t, []string{"authorization_code"}, data.GrantTypes)
						require.Equal(t, []string{"code"}, data.ResponseTypes)
						require.Equal(t, "foo bar", data.Scope)
						require.Equal(t, "https://example.com/logo.png", data.LogoURI)
						require.Equal(t, []string{"contact1@example.com", "contact2@example.com"}, data.Contacts)
						require.Equal(t, "https://example.com/toc.html", data.TermsOfServiceURI)
						require.Equal(t, "https://example.com/policy.html", data.PolicyURI)
						require.Equal(t, "https://example.com/.well-known/jwks.json", data.JSONWebKeysURI)
						require.Empty(t, data.JSONWebKeys)
						require.Empty(t, data.SoftwareID)
						require.Empty(t, data.SoftwareVersion)
						require.Equal(t, "client_secret_basic", data.TokenEndpointAuthMethod)

						return &oauth2client.Client{}, nil
					},
				)

				b, err := json.Marshal(&clientidscheme.ClientMetadataResponse{
					ClientName:              "test-client",
					ClientURI:               "https://example.com/test-client",
					RedirectURIs:            []string{"https://example.com/cb"},
					GrantTypes:              []string{"authorization_code"},
					ResponseTypes:           []string{"code"},
					Scope:                   "foo bar",
					LogoURI:                 "https://example.com/logo.png",
					Contacts:                []string{"contact1@example.com", "contact2@example.com"},
					TermsOfServiceURI:       "https://example.com/toc.html",
					PolicyURI:               "https://example.com/policy.html",
					JSONWebKeysURI:          "https://example.com/.well-known/jwks.json",
					JSONWebKeys:             nil,
					TokenEndpointAuthMethod: "client_secret_basic",
				})
				require.NoError(t, err)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					require.Equal(t, "https://example.com/.well-known/oauth-client/test-client", req.URL.String())

					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer(b)),
					}, nil
				})

				profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: true,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "success: wallet-initiated flow",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "https://example.com/issuer/profileID/profileVersion"

				clientManager.EXPECT().Get(gomock.Any(), clientURI).Return(nil, clientmanager.ErrClientNotFound)

				clientManager.EXPECT().Create(gomock.Any(), "profileID", "profileVersion", gomock.Any()).
					Return(&oauth2client.Client{}, nil)

				b, err := json.Marshal(&clientidscheme.ClientMetadataResponse{
					ClientName:              "test-client",
					ClientURI:               "https://example.com/test-client",
					RedirectURIs:            []string{"https://example.com/cb"},
					GrantTypes:              []string{"authorization_code"},
					ResponseTypes:           []string{"code"},
					Scope:                   "foo bar",
					TokenEndpointAuthMethod: "client_secret_basic",
				})
				require.NoError(t, err)

				httpClient.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
					require.Equal(t, "https://example.com/.well-known/oauth-client/test-client", req.URL.String())

					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer(b)),
					}, nil
				})

				profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: true,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(nil, resterr.ErrDataNotFound)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "success: client already exists",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "invalid state"

				clientManager.EXPECT().Get(gomock.Any(), gomock.Any()).Return(&oauth2client.Client{}, nil)
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: true,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "invalid issuer state in wallet-initiated flow",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "invalid state"

				clientManager.EXPECT().Get(gomock.Any(), gomock.Any()).Times(0)
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)
				profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Times(0)
				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(nil, resterr.ErrDataNotFound)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "issuer state expected to be uri that ends with profile id and version")
			},
		},
		{
			name: "fail to find tx by op state",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "invalid state"

				clientManager.EXPECT().Get(gomock.Any(), gomock.Any()).Times(0)
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				httpClient.EXPECT().Do(gomock.Any()).Times(0)
				profileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Times(0)
				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(nil, errors.New("error find by op state"))
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "find tx by op state:")
			},
		},
		{
			name: "fail to get profile",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "issuer state"

				clientManager.EXPECT().Get(gomock.Any(), gomock.Any()).Times(0)
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				profileService.EXPECT().GetProfile("profileID", "profileVersion").
					Return(nil, errors.New("get profile error"))

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "get profile:")
			},
		},
		{
			name: "discoverable client id scheme not enabled",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "invalid state"

				clientManager.EXPECT().Get(gomock.Any(), gomock.Any()).Times(0)
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				profileService.EXPECT().GetProfile("profileID", "profileVersion").Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: false,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "profile profileID doesn't support discoverable client ID scheme")
			},
		},
		{
			name: "fail to get client",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "issuer state"

				clientManager.EXPECT().Get(gomock.Any(), clientURI).Return(nil, errors.New("get error"))
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				httpClient.EXPECT().Do(gomock.Any()).Times(0)

				profileService.EXPECT().GetProfile("profileID", "profileVersion").Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: true,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "get client:")
			},
		},
		{
			name: "fail to get client metadata",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "issuer state"

				clientManager.EXPECT().Get(gomock.Any(), clientURI).Return(nil, clientmanager.ErrClientNotFound)
				clientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				}, nil)

				profileService.EXPECT().GetProfile("profileID", "profileVersion").Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: true,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "get client metadata:")
			},
		},
		{
			name: "fail to create client",
			setup: func() {
				clientURI = "https://example.com/test-client"
				issuerState = "issuer state"

				clientManager.EXPECT().Get(gomock.Any(), clientURI).Return(nil, clientmanager.ErrClientNotFound)

				clientManager.EXPECT().Create(gomock.Any(), "profileID", "profileVersion", gomock.Any()).
					Return(nil, errors.New("create error"))

				b, err := json.Marshal(&clientidscheme.ClientMetadataResponse{
					ClientName:              "test-client",
					ClientURI:               "https://example.com/test-client",
					RedirectURIs:            []string{"https://example.com/cb"},
					GrantTypes:              []string{"authorization_code"},
					ResponseTypes:           []string{"code"},
					TokenEndpointAuthMethod: "client_secret_basic",
				})
				require.NoError(t, err)

				httpClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(b)),
				}, nil)

				profileService.EXPECT().GetProfile("profileID", "profileVersion").Return(&profileapi.Issuer{
					OIDCConfig: &profileapi.OIDCConfig{
						EnableDiscoverableClientIDScheme: true,
					},
				}, nil)

				store.EXPECT().FindByOpState(gomock.Any(), issuerState).Return(&issuecredential.Transaction{
					TransactionData: issuecredential.TransactionData{
						ProfileID:      "profileID",
						ProfileVersion: "profileVersion",
					},
				}, nil)
			},
			check: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "create client:")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc := clientidscheme.NewService(&clientidscheme.Config{
				ClientManager:    clientManager,
				HTTPClient:       httpClient,
				ProfileService:   profileService,
				TransactionStore: store,
			})

			err := svc.Register(context.Background(), clientURI, issuerState)
			tt.check(t, err)
		})
	}
}
