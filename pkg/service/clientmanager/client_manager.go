/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination client_manager_mocks_test.go -package clientmanager_test -source=client_manager.go -mock_names store=MockStore,profileService=MockProfileService

package clientmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/samber/lo"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var _ ServiceInterface = (*Manager)(nil)

const (
	defaultInitialAccessTokenLifespan = 5 * time.Minute
	defaultTokenEndpointAuthMethod    = "client_secret_basic"
)

type store interface {
	InsertClient(ctx context.Context, client *oauth2client.Client) (string, error)
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
		return nil, fmt.Errorf("oidc not configured")
	}

	client := &oauth2client.Client{
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

	if err = setScopes(client, profile.OIDCConfig.ScopesSupported, data.Scope); err != nil {
		return nil, err
	}

	if err = setGrantTypes(client, profile.OIDCConfig.GrantTypesSupported, data.GrantTypes); err != nil {
		return nil, err
	}

	if err = setResponseTypes(client, profile.OIDCConfig.ResponseTypesSupported, data.ResponseTypes); err != nil {
		return nil, err
	}

	if err = setTokenEndpointAuthMethod(
		client,
		profile.OIDCConfig.TokenEndpointAuthMethodsSupported,
		data.TokenEndpointAuthMethod,
	); err != nil {
		return nil, err
	}

	if err = setJSONWebKeys(client, data.JSONWebKeys); err != nil {
		return nil, err
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	client.Secret = secret

	if profile.OIDCConfig.InitialAccessTokenLifespan != 0 {
		client.SecretExpiresAt = time.Now().Add(profile.OIDCConfig.InitialAccessTokenLifespan)
	} else {
		client.SecretExpiresAt = time.Now().Add(defaultInitialAccessTokenLifespan)
	}

	if err = validateClient(client); err != nil {
		return nil, err
	}

	clientID, err := m.store.InsertClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	client.ID = clientID

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
			return &RegistrationError{
				Code:        ErrCodeInvalidClientMetadata,
				Description: fmt.Sprintf("scope %s not supported", s),
			}
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
			return &RegistrationError{
				Code:        ErrCodeInvalidClientMetadata,
				Description: fmt.Sprintf("grant type %s not supported", gt),
			}
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
			return &RegistrationError{
				Code:        ErrCodeInvalidClientMetadata,
				Description: fmt.Sprintf("response type %s not supported", rt),
			}
		}
	}

	client.ResponseTypes = responseTypes

	return nil
}

func setTokenEndpointAuthMethod(client *oauth2client.Client, methodsSupported []string, method string) error {
	if method == "" {
		if len(methodsSupported) == 0 || lo.Contains(methodsSupported, defaultTokenEndpointAuthMethod) {
			client.TokenEndpointAuthMethod = defaultTokenEndpointAuthMethod
		} else {
			client.TokenEndpointAuthMethod = methodsSupported[0]
		}

		return nil
	}

	if !lo.Contains(methodsSupported, method) {
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: fmt.Sprintf("token endpoint auth method %s not supported", method),
		}
	}

	client.TokenEndpointAuthMethod = method

	return nil
}

func setJSONWebKeys(client *oauth2client.Client, rawJWKs map[string]interface{}) error {
	b, err := json.Marshal(rawJWKs)
	if err != nil {
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: fmt.Sprintf("invalid jwks: %s", err.Error()),
		}
	}

	var jwks jose.JSONWebKeySet

	if err = json.Unmarshal(b, &jwks); err != nil {
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: fmt.Sprintf("invalid jwks format: %s", err.Error()),
		}
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
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: "jwks_uri and jwks cannot both be set",
		}
	}

	if lo.Contains(client.GrantTypes, "authorization_code") && client.RedirectURIs == nil {
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: "redirect_uris must be set for authorization_code grant type",
		}
	}

	// validate relationship between Grant Types and Response Types
	// https://datatracker.ietf.org/doc/html/rfc7591#section-2.1
	if lo.Contains(client.GrantTypes, "authorization_code") && !lo.Contains(client.ResponseTypes, "code") {
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: "authorization_code grant type requires code response type",
		}
	}

	if lo.Contains(client.GrantTypes, "implicit") && !lo.Contains(client.ResponseTypes, "token") {
		return &RegistrationError{
			Code:        ErrCodeInvalidClientMetadata,
			Description: "implicit grant type requires token response type",
		}
	}

	return nil
}
