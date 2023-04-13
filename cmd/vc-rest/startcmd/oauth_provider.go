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
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"

	fositedto "github.com/trustbloc/vcs/component/oidc/fosite/dto"
	fositemongo "github.com/trustbloc/vcs/component/oidc/fosite/mongo"
	fositeredis "github.com/trustbloc/vcs/component/oidc/fosite/redis"
	fosite_ext "github.com/trustbloc/vcs/pkg/restapi/handlers"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const redisOAuthStore = "redis"

func bootstrapOAuthProvider(
	ctx context.Context,
	secret string,
	oauthStore string,
	mongoClient *mongodb.Client,
	redisClient redis.UniversalClient,
	oauth2Clients []fositedto.Client,
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

	store, err := bootstrapOAuthStorage(ctx, oauthStore, mongoClient, redisClient, oauth2Clients)
	if err != nil {
		return nil, err
	}

	return compose.Compose(config, store, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
		compose.OAuth2TokenIntrospectionFactory,
		fosite_ext.OAuth2PreAuthorizeFactory,
	), nil
}

func bootstrapOAuthStorage(
	ctx context.Context,
	oauthStore string,
	mongoClient *mongodb.Client,
	redisClient redis.UniversalClient,
	oauth2Clients []fositedto.Client) (interface{}, error) {
	var store interface{}
	var err error
	switch oauthStore {
	case redisOAuthStore:
		logger.Info("Redis oAuth store is used")
		store = fositeredis.NewStore(redisClient)
	default:
		store, err = fositemongo.NewStore(ctx, mongoClient)
		if err != nil {
			return nil, err
		}
		logger.Info("Mongo oAuth store is used")
	}

	if inserter, ok := store.(interface {
		InsertClient(ctx context.Context, client fositedto.Client) (string, error)
	}); ok {
		for _, c := range oauth2Clients {
			if _, err = inserter.InsertClient(ctx, c); err != nil {
				if mongo.IsDuplicateKeyError(err) {
					continue
				}

				return nil, err
			}
		}
	}

	return store, nil
}
