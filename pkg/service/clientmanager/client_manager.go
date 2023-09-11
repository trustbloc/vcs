/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_manager_mocks_test.go -package clientmanager_test -source=client_manager.go -mock_names store=MockStore,profileService=MockProfileService

package clientmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/samber/lo"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var _ ServiceInterface = (*Manager)(nil)

type store interface {
	InsertClient(ctx context.Context, client *oauth2client.Client) (string, error)
	GetClient(ctx context.Context, id string) (fosite.Client, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

// Config defines configuration for client manager.
type Config struct {
	Store          store
	ProfileService profileService
}

// Manager implements functionality to manage OAuth2 clients.
type Manager struct {
	store          store
	profileService profileService
}

// New creates a new Manager instance.
func New(config *Config) *Manager {
	return &Manager{
		store:          config.Store,
		profileService: config.ProfileService,
	}
}

// ClientMetadata contains the metadata for an OAuth2 client.
type ClientMetadata struct {
	ID                      string
	Name                    string
	URI                     string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scope                   string
	LogoURI                 string
	Contacts                []string
	TermsOfServiceURI       string
	PolicyURI               string
	JSONWebKeysURI          string
	JSONWebKeys             map[string]interface{}
	SoftwareID              string
	SoftwareVersion         string
	TokenEndpointAuthMethod string
}

// Create creates an OAuth2 client and inserts it into the store.
func (m *Manager) Create(ctx context.Context, profileID, profileVersion string, data *ClientMetadata) (*oauth2client.Client, error) { // nolint:lll
	profile, err := m.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}

	if profile.OIDCConfig == nil {
		return nil, fmt.Errorf("oidc config not set for profile")
	}

	client := &oauth2client.Client{
		ID:                data.ID,
		Name:              data.Name,
		URI:               data.URI,
		RedirectURIs:      data.RedirectURIs,
		LogoURI:           data.LogoURI,
		Contacts:          data.Contacts,
		TermsOfServiceURI: data.TermsOfServiceURI,
		PolicyURI:         data.PolicyURI,
		JSONWebKeysURI:    data.JSONWebKeysURI,
		SoftwareID:        data.SoftwareID,
		SoftwareVersion:   data.SoftwareVersion,
		CreatedAt:         time.Now(),
	}

	if client.ID == "" {
		client.ID = uuid.New().String()
	}

	if err = setScopes(client, profile.OIDCConfig.ScopesSupported, data.Scope); err != nil {
		return nil, InvalidClientMetadataError("scope", err)
	}

	if err = setGrantTypes(client, oauth2client.GrantTypesSupported(), data.GrantTypes); err != nil {
		return nil, InvalidClientMetadataError("grant_types", err)
	}

	if err = setResponseTypes(client, oauth2client.ResponseTypesSupported(), data.ResponseTypes); err != nil {
		return nil, InvalidClientMetadataError("response_types", err)
	}

	if err = setTokenEndpointAuthMethod(
		client,
		oauth2client.TokenEndpointAuthMethodsSupported(),
		data.TokenEndpointAuthMethod,
	); err != nil {
		return nil, InvalidClientMetadataError("token_endpoint_auth_method", err)
	}

	if client.TokenEndpointAuthMethod != oauth2client.TokenEndpointAuthMethodNone {
		var secret []byte

		if secret, err = generateSecret(); err != nil {
			return nil, err
		}

		client.Secret = secret
		client.SecretExpiresAt = 0 // never expires
	}

	if err = setJSONWebKeys(client, data.JSONWebKeys); err != nil {
		return nil, InvalidClientMetadataError("jwks", err)
	}

	if err = validateClient(client); err != nil {
		return nil, err
	}

	if _, err = m.store.InsertClient(ctx, client); err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	return client, nil
}

func setScopes(client *oauth2client.Client, scopesSupported []string, scope string) error {
	if scope == "" {
		client.Scopes = scopesSupported
		return nil
	}

	scopes := strings.Split(scope, " ")

	for _, s := range scopes {
		if !lo.Contains(scopesSupported, s) {
			return fmt.Errorf("scope %s not supported", s)
		}
	}

	client.Scopes = scopes

	return nil
}

func setGrantTypes(client *oauth2client.Client, grantTypesSupported []string, grantTypes []string) error {
	if len(grantTypes) == 0 {
		client.GrantTypes = grantTypesSupported
		return nil
	}

	for _, gt := range grantTypes {
		if !lo.Contains(grantTypesSupported, gt) {
			return fmt.Errorf("grant type %s not supported", gt)
		}
	}

	client.GrantTypes = grantTypes

	return nil
}

func setResponseTypes(client *oauth2client.Client, responseTypesSupported []string, responseTypes []string) error {
	if len(responseTypes) == 0 {
		client.ResponseTypes = responseTypesSupported
		return nil
	}

	for _, rt := range responseTypes {
		if !lo.Contains(responseTypesSupported, rt) {
			return fmt.Errorf("response type %s not supported", rt)
		}
	}

	client.ResponseTypes = responseTypes

	return nil
}

func setTokenEndpointAuthMethod(client *oauth2client.Client, methodsSupported []string, method string) error {
	if method == "" {
		client.TokenEndpointAuthMethod = oauth2client.TokenEndpointAuthMethodClientSecretBasic
		return nil
	}

	if !lo.Contains(methodsSupported, method) {
		return fmt.Errorf("token endpoint auth method %s not supported", method)
	}

	client.TokenEndpointAuthMethod = method

	return nil
}

func setJSONWebKeys(client *oauth2client.Client, rawJWKs map[string]interface{}) error {
	if len(rawJWKs) == 0 {
		return nil
	}

	b, err := json.Marshal(rawJWKs)
	if err != nil {
		return fmt.Errorf("marshal raw jwks: %w", err)
	}

	var jwks jose.JSONWebKeySet

	if err = json.Unmarshal(b, &jwks); err != nil {
		return fmt.Errorf("unmarshal raw jwks into key set: %w", err)
	}

	client.JSONWebKeys = &jwks

	return nil
}

func generateSecret() ([]byte, error) {
	secret, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}

	b, err := secret.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal secret: %w", err)
	}

	return b, nil
}

func validateClient(client *oauth2client.Client) error {
	if client.JSONWebKeysURI != "" && client.JSONWebKeys != nil {
		return InvalidClientMetadataError("", fmt.Errorf("jwks_uri and jwks cannot both be set"))
	}

	if len(client.RedirectURIs) > 0 {
		for _, uri := range client.RedirectURIs {
			if u, err := url.Parse(uri); err == nil && isValidRedirectURI(u) {
				continue
			}

			return &RegistrationError{
				Code:         ErrCodeInvalidRedirectURI,
				InvalidValue: "redirect_uris",
				Err:          fmt.Errorf("invalid redirect uri: %s", uri),
			}
		}
	}

	if lo.Contains(client.GrantTypes, "authorization_code") && client.RedirectURIs == nil {
		return &RegistrationError{
			Code:         ErrCodeInvalidRedirectURI,
			InvalidValue: "redirect_uris",
			Err:          fmt.Errorf("redirect_uris must be set for authorization_code grant type"),
		}
	}

	return nil
}

func isValidRedirectURI(uri *url.URL) bool {
	u, err := url.ParseRequestURI(uri.String())
	if err != nil {
		return false
	}

	if len(u.Scheme) == 0 {
		return false
	}

	if uri.Fragment != "" {
		return false
	}

	return true
}

// Get returns the fosite client with the given id.
func (m *Manager) Get(ctx context.Context, id string) (fosite.Client, error) {
	c, err := m.store.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, dto.ErrDataNotFound) {
			return nil, ErrClientNotFound
		}

		return nil, fmt.Errorf("get client: %w", err)
	}

	return c, nil
}
