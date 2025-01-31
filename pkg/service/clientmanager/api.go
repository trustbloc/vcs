/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager

import (
	"context"
	"errors"

	"github.com/ory/fosite"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

// ServiceInterface defines an interface for OAuth2 client manager.
type ServiceInterface interface {
	Create(ctx context.Context, profileID, profileVersion string, data *ClientMetadata) (*oauth2client.Client, error) //nolint:lll // *rfc7591.Error
	Get(ctx context.Context, id string) (fosite.Client, error)
}

var (
	ErrClientNotFound = errors.New("client not found")
)
