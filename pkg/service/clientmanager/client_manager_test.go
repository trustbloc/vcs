/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
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
								ScopesSupported:                   []string{"foo", "bar"},
								GrantTypesSupported:               []string{"authorization_code"},
								ResponseTypesSupported:            []string{"code"},
								TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Return(uuid.New().String(), nil)

				data = &clientmanager.ClientMetadata{
					Scope:        "foo",
					RedirectURIs: []string{"https://example.com/redirect"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
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
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "get profile:")
			},
		},
		{
			name: "oidc not configured",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(&profileapi.Issuer{}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "oidc not configured")
			},
		},
		{
			name: "not supported scope error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								ScopesSupported: []string{"foo", "bar"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					Scope: "baz",
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "scope baz not supported")
			},
		},
		{
			name: "not supported grant type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								GrantTypesSupported: []string{"authorization_code"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					GrantTypes: []string{"client_credentials"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "grant type client_credentials not supported")
			},
		},
		{
			name: "not supported response type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								ResponseTypesSupported: []string{"code"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					ResponseTypes: []string{"code", "token"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "response type token not supported")
			},
		},
		{
			name: "not supported token endpoint auth method error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					TokenEndpointAuthMethod: "none",
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "token endpoint auth method none not supported")
			},
		},
		{
			name: "invalid jwks error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					JSONWebKeys: map[string]interface{}{"keys": func() {}},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "invalid jwks:")
			},
		},
		{
			name: "invalid jwks format error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					JSONWebKeys: map[string]interface{}{"keys": "invalid"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "invalid jwks format:")
			},
		},
		{
			name: "jwks_uri and jwks cannot both be set error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{},
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
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "jwks_uri and jwks cannot both be set")
			},
		},
		{
			name: "redirect_uris must be set for authorization_code grant type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								GrantTypesSupported: []string{"authorization_code"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					GrantTypes: []string{"authorization_code"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "redirect_uris must be set for authorization_code grant type")
			},
		},
		{
			name: "authorization_code grant type requires code response type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								GrantTypesSupported:    []string{"authorization_code", "implicit"},
								ResponseTypesSupported: []string{"code", "token"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					GrantTypes:    []string{"authorization_code"},
					ResponseTypes: []string{"token"},
					RedirectURIs:  []string{"https://example.com/redirect"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "authorization_code grant type requires code response type")
			},
		},
		{
			name: "implicit grant type requires token response type error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								GrantTypesSupported:    []string{"authorization_code", "implicit"},
								ResponseTypesSupported: []string{"code", "token"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					GrantTypes:    []string{"implicit"},
					ResponseTypes: []string{"code"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "implicit grant type requires token response type")
			},
		},
		{
			name: "invalid redirect uri",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					RedirectURIs: []string{"invalid"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "invalid redirect uri")
			},
		},
		{
			name: "invalid scheme in redirect uri",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					RedirectURIs: []string{"//example.com/redirect"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "invalid redirect uri")
			},
		},
		{
			name: "redirect uri must not include a fragment component",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Times(0)

				data = &clientmanager.ClientMetadata{
					RedirectURIs: []string{"https://example.com/redirect#fragment"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "invalid redirect uri")
			},
		},
		{
			name: "insert client store error",
			setup: func() {
				mockProfileSvc.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(
						&profileapi.Issuer{
							OIDCConfig: &profileapi.OIDCConfig{
								ScopesSupported:        []string{"foo", "bar"},
								GrantTypesSupported:    []string{"authorization_code"},
								ResponseTypesSupported: []string{"code"},
							},
						}, nil)

				mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("insert error"))

				data = &clientmanager.ClientMetadata{
					Scope:        "foo",
					RedirectURIs: []string{"https://example.com/redirect"},
				}
			},
			check: func(t *testing.T, client *oauth2client.Client, err error) {
				require.ErrorContains(t, err, "insert client:")
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
