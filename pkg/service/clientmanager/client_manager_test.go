/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc7591"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	clientmanagerstore "github.com/trustbloc/vcs/pkg/storage/mongodb/clientmanager"
)

func TestManager_Create(t *testing.T) {
	var (
		mockStore      = NewMockStore(gomock.NewController(t))
		mockProfileSvc = NewMockProfileService(gomock.NewController(t))
		data           *clientmanager.ClientMetadata
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, client *oauth2client.Client, err error)
	}{
		{
			name: "success",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								ScopesSupported:                 []string{"foo", "bar"},
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Return(uuid.New().String(), nil)

				data = &clientmanager.ClientMetadata{
					Scope:                   "foo",
					GrantTypes:              []string{"authorization_code"},
					ResponseTypes:           []string{"code"},
					TokenEndpointAuthMethod: "client_secret_basic",
					RedirectURIs:            []string{"https://example.com/redirect"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "get profile error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(nil, fmt.Errorf("get profile error"))

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "get profile:")
			},
		},
		{
			name: "empty oidc config",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(&profileapi.Issuer{}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "oidc config not set for profile")
			},
		},
		{
			name: "not supported scope error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								ScopesSupported:                 []string{"foo", "bar"},
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					Scope: "baz",
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "scope", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "scope baz not supported")
			},
		},
		{
			name: "not supported grant type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					GrantTypes: []string{"client_credentials"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "grant_types", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "grant type client_credentials not supported")
			},
		},
		{
			name: "not supported response type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					ResponseTypes: []string{"code", "token"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "response_types", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "response type token not supported")
			},
		},
		{
			name: "not supported token endpoint auth method error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					TokenEndpointAuthMethod: "not_supported_auth_method",
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "token_endpoint_auth_method", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "token endpoint auth method not_supported_auth_method not supported")
			},
		},
		{
			name: "marshal raw jwks error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					JSONWebKeys: map[string]interface{}{"keys": func() {}},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "jwks", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "marshal raw jwks:")
			},
		},
		{
			name: "unmarshal raw jwks into key set error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					JSONWebKeys: map[string]interface{}{"keys": "invalid"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "jwks", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "unmarshal raw jwks into key set:")
			},
		},
		{
			name: "jwks_uri and jwks cannot both be set error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				b, err := json.Marshal(jose.JSONWebKeySet{})
				require.NoError(t, err)

				var m map[string]interface{}
				require.NoError(t, json.Unmarshal(b, &m))

				data = &clientmanager.ClientMetadata{
					JSONWebKeysURI: "https://example.com/jwks.json",
					JSONWebKeys:    m,
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_client_metadata", regErr.Code())
				require.Equal(t, "", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "jwks_uri and jwks cannot both be set")
			},
		},
		{
			name: "redirect_uris must be set for authorization_code grant type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					GrantTypes: []string{"authorization_code"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_redirect_uri", regErr.Code())
				require.Equal(t, "redirect_uris", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "redirect_uris must be set for authorization_code grant type")
			},
		},
		{
			name: "invalid redirect uri",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					RedirectURIs: []string{"invalid"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_redirect_uri", regErr.Code())
				require.Equal(t, "redirect_uris", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "invalid redirect uri: invalid")
			},
		},
		{
			name: "invalid scheme in redirect uri",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					RedirectURIs: []string{"//example.com/redirect"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_redirect_uri", regErr.Code())
				require.Equal(t, "redirect_uris", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "invalid redirect uri: //example.com/redirect")
			},
		},
		{
			name: "redirect uri must not include a fragment component",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					RedirectURIs: []string{"https://example.com/redirect#fragment"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				var regErr *rfc7591.Error

				require.ErrorAs(t, err, &regErr)
				require.Equal(t, "invalid_redirect_uri", regErr.Code())
				require.Equal(t, "redirect_uris", regErr.IncorrectValue)
				require.ErrorContains(t, regErr, "invalid redirect uri: https://example.com/redirect#fragment")
			},
		},
		{
			name: "insert client store error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								ScopesSupported:                 []string{"foo", "bar"},
								EnableDynamicClientRegistration: true,
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("insert error"))

				data = &clientmanager.ClientMetadata{
					Scope:        "foo",
					RedirectURIs: []string{"https://example.com/redirect"},
				}
			},
			check: func(t *testing.T, _ *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "insert client: insert error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			manager := clientmanager.New(
				&clientmanager.Config{
					Store:          mockStore,
					ProfileService: mockProfileSvc,
				},
			)

			client, err := manager.Create(context.Background(), "test", "v1", data)
			tt.check(t, client, err)
		})
	}
}

func TestManager_Get(t *testing.T) {
	const clientID = "test-client-id"

	mockStore := NewMockStore(gomock.NewController(t))

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, client fosite.Client, err error)
	}{
		{
			name: "success",
			setup: func() {
				mockStore.EXPECT().GetClient(gomock.Any(), clientID).Return(&oauth2client.Client{}, nil)
			},
			check: func(t *testing.T, _ fosite.Client, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "client not found error",
			setup: func() {
				mockStore.EXPECT().GetClient(gomock.Any(), clientID).Return(nil, clientmanagerstore.ErrDataNotFound)
			},
			check: func(t *testing.T, _ fosite.Client, err error) {
				require.ErrorIs(t, err, clientmanager.ErrClientNotFound)
			},
		},
		{
			name: "fail to get client",
			setup: func() {
				mockStore.EXPECT().GetClient(gomock.Any(), clientID).Return(nil, errors.New("get client error"))
			},
			check: func(t *testing.T, _ fosite.Client, err error) {
				require.ErrorContains(t, err, "get client:")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			manager := clientmanager.New(
				&clientmanager.Config{
					Store: mockStore,
				},
			)

			client, err := manager.Get(context.Background(), clientID)
			tt.check(t, client, err)
		})
	}
}
