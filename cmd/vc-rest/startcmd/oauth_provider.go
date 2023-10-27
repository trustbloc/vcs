/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/hmac"

	fositemongo "github.com/trustbloc/vcs/component/oidc/fosite/mongo"
	fositeredis "github.com/trustbloc/vcs/component/oidc/fosite/redis"
	fositeext "github.com/trustbloc/vcs/pkg/restapi/handlers"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/clientmanager"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

func bootstrapOAuthProvider(
	ctx context.Context,
	secret string,
	transientDataStoreType string,
	mongoClient *mongodb.Client,
	redisClient *redis.Client,
	clientManager *clientmanager.Store,
) (fosite.OAuth2Provider, error) {
	if len(secret) == 0 {
		return nil, errors.New("invalid secret")
	}

	config := new(fosite.Config)
	config.GlobalSecret = []byte(secret)
	config.AuthorizeCodeLifespan = 30 * time.Minute
	config.AccessTokenLifespan = 30 * time.Minute
	config.SendDebugMessagesToClients = true // TODO: Disable before moving to production.

	var hmacStrategy = &fositeoauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			Config: config,
		},
		Config: config,
	}

	var store interface{}

	switch transientDataStoreType {
	case redisStore:
		store = fositeredis.NewStore(redisClient, clientManager)
		logger.Info("Redis OAuth store is used")
	default:
		s, err := fositemongo.NewStore(ctx, mongoClient, clientManager)
		if err != nil {
			return nil, err
		}
		store = s
		logger.Info("MongoDB OAuth store is used")
	}

	return compose.Compose(config, store, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
		compose.OAuth2TokenIntrospectionFactory,
		fositeext.OAuth2PreAuthorizeFactory,
	), nil
}
