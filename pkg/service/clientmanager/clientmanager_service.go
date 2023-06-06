/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination clientmanager_service_mocks_test.go -package clientmanager_test -source=clientmanager_service.go -mock_names store=MockStore

package clientmanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

type store interface {
	InsertClient(ctx context.Context, client oauth2client.Client) (string, error)
}

// Service is an OAuth2 client service.
type Service struct {
	store store
}

// NewService creates a new Service instance.
func NewService(store store) *Service {
	return &Service{
		store: store,
	}
}

// ClientMetadata contains the metadata for an OAuth2 client.
type ClientMetadata struct {
	Name                    string   `json:"client_name"`
	URI                     string   `json:"client_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// CreateClient creates an OAuth2 client and inserts it into the store.
func (s *Service) CreateClient(ctx context.Context, data *ClientMetadata) (*oauth2client.Client, error) {
	// TODO: validate request

	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	oauth2Client := oauth2client.Client{
		Secret:        secret,
		RedirectURIs:  data.RedirectURIs,
		GrantTypes:    data.GrantTypes,
		ResponseTypes: data.ResponseTypes,
		Scopes:        strings.Split(data.Scope, " "),
	}

	clientID, err := s.store.InsertClient(ctx, oauth2Client)
	if err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	oauth2Client.ID = clientID

	return &oauth2Client, nil
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
