/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination clientidscheme_service_mocks_test.go -package clientidscheme_test -source=clientidscheme_service.go -mock_names clientManager=MockClientManager,httpClient=MockHTTPClient,profileService=MockProfileService,transactionStore=MockTransactionStore

package clientidscheme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"

	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	wellKnownURISuffix = "oauth-client"
	issuerURIMinParts  = 2
)

type clientManager interface {
	Create(ctx context.Context, profileID, profileVersion string, data *clientmanager.ClientMetadata) (*oauth2client.Client, error) //nolint:lll
	Get(ctx context.Context, id string) (fosite.Client, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type profileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

type transactionStore interface {
	FindByOpState(ctx context.Context, opState string) (*oidc4ci.Transaction, error)
}

// Config defines configuration for Service.
type Config struct {
	ClientManager    clientManager
	HTTPClient       httpClient
	ProfileService   profileService
	TransactionStore transactionStore
}

// Service implements functionality for discoverable client ID scheme.
type Service struct {
	clientManager    clientManager
	httpClient       httpClient
	profileService   profileService
	transactionStore transactionStore
}

// NewService returns a new Service instance.
func NewService(config *Config) *Service {
	return &Service{
		clientManager:    config.ClientManager,
		httpClient:       config.HTTPClient,
		profileService:   config.ProfileService,
		transactionStore: config.TransactionStore,
	}
}

// Register registers a new OAuth client with clientURI ID. If client with given ID already exists, it does nothing.
func (s *Service) Register(ctx context.Context, clientURI, issuerState string) error {
	profileID, profileVersion, err := s.getProfileID(ctx, issuerState)
	if err != nil {
		return err
	}

	profile, err := s.profileService.GetProfile(profileID, profileVersion)
	if err != nil {
		return fmt.Errorf("get profile: %w", err)
	}

	if profile.OIDCConfig == nil || !profile.OIDCConfig.EnableDiscoverableClientIDScheme {
		return fmt.Errorf("profile %s doesn't support discoverable client ID scheme", profileID)
	}

	_, err = s.clientManager.Get(ctx, clientURI)
	if err == nil {
		return nil // client already exists
	}

	if !errors.Is(err, clientmanager.ErrClientNotFound) {
		return fmt.Errorf("get client: %w", err)
	}

	data, err := s.getClientMetadata(ctx, clientURI)
	if err != nil {
		return fmt.Errorf("get client metadata: %w", err)
	}

	_, err = s.clientManager.Create(ctx, profileID, profileVersion,
		&clientmanager.ClientMetadata{
			ID:                      clientURI,
			Name:                    data.ClientName,
			URI:                     data.ClientURI,
			RedirectURIs:            data.RedirectURIs,
			GrantTypes:              data.GrantTypes,
			ResponseTypes:           data.ResponseTypes,
			Scope:                   data.Scope,
			LogoURI:                 data.LogoURI,
			Contacts:                data.Contacts,
			TermsOfServiceURI:       data.TermsOfServiceURI,
			PolicyURI:               data.PolicyURI,
			JSONWebKeysURI:          data.JSONWebKeysURI,
			JSONWebKeys:             data.JSONWebKeys,
			SoftwareID:              data.SoftwareID,
			SoftwareVersion:         data.SoftwareVersion,
			TokenEndpointAuthMethod: data.TokenEndpointAuthMethod,
		},
	)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	return nil
}

func (s *Service) getProfileID(ctx context.Context, issuerState string) (string, string, error) {
	t, err := s.transactionStore.FindByOpState(ctx, issuerState)
	if err != nil {
		if errors.Is(err, resterr.ErrDataNotFound) {
			// wallet-initiated flow
			a := strings.Split(issuerState, "/")
			if len(a) < issuerURIMinParts {
				return "", "", errors.New("issuer state expected to be uri that ends with profile id and version")
			}

			return a[len(a)-2], a[len(a)-1], nil
		}

		return "", "", fmt.Errorf("find tx by op state: %w", err)
	}

	return t.ProfileID, t.ProfileVersion, nil
}

// ClientMetadataResponse represents a client metadata response from client's well-known uri.
type ClientMetadataResponse struct {
	ClientName              string                 `json:"client_name"`
	ClientURI               string                 `json:"client_uri"`
	RedirectURIs            []string               `json:"redirect_uris"`
	GrantTypes              []string               `json:"grant_types"`
	ResponseTypes           []string               `json:"response_types"`
	Scope                   string                 `json:"scope"`
	LogoURI                 string                 `json:"logo_uri"`
	Contacts                []string               `json:"contacts"`
	TermsOfServiceURI       string                 `json:"tos_uri"`
	PolicyURI               string                 `json:"policy_uri"`
	JSONWebKeysURI          string                 `json:"jwks_uri"`
	JSONWebKeys             map[string]interface{} `json:"jwks"`
	SoftwareID              string                 `json:"software_id"`
	SoftwareVersion         string                 `json:"software_version"`
	TokenEndpointAuthMethod string                 `json:"token_endpoint_auth_method"`
}

func (s *Service) getClientMetadata(ctx context.Context, clientURI string) (*ClientMetadataResponse, error) {
	u, err := buildOAuthClientWellKnownURI(clientURI)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s failed with status: %d", u, resp.StatusCode)
	}

	var data ClientMetadataResponse

	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}

	return &data, nil
}

// The client metadata should be available at a path formed by inserting a well-known URI string into the client_uri
// between the host component and the path component, if any. By default, the well-known URI string used
// is "/.well-known/oauth-client".
func buildOAuthClientWellKnownURI(clientURI string) (string, error) {
	u, err := url.Parse(clientURI)
	if err != nil {
		return "", fmt.Errorf("parse client uri: %w", err)
	}

	u.Path, _ = url.JoinPath(".well-known", wellKnownURISuffix, u.Path)

	return u.String(), nil
}
