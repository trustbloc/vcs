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
	"go.mongodb.org/mongo-driver/mongo"

	fositemongo "github.com/trustbloc/vcs/component/oidc/fosite/mongo"
	fositeredis "github.com/trustbloc/vcs/component/oidc/fosite/redis"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	fositeext "github.com/trustbloc/vcs/pkg/restapi/handlers"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/redis"
)

type oauth2ClientStore interface {
	InsertClient(ctx context.Context, client oauth2client.Client) (string, error)
}

func bootstrapOAuthProvider(
	ctx context.Context,
	secret string,
	transientDataStoreType string,
	mongoClient *mongodb.Client,
	redisClient *redis.Client,
	oauth2Clients []oauth2client.Client,
) (fosite.OAuth2Provider, interface{}, error) {
	if len(secret) == 0 {
		return nil, nil, errors.New("invalid secret")
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

	store, err := bootstrapOAuthStorage(ctx, transientDataStoreType, mongoClient, redisClient, oauth2Clients)
	if err != nil {
		return nil, nil, err
	}

	return compose.Compose(config, store, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
		compose.OAuth2TokenIntrospectionFactory,
		fositeext.OAuth2PreAuthorizeFactory,
	), store, nil
}

func bootstrapOAuthStorage(
	ctx context.Context,
	transientDataStoreType string,
	mongoClient *mongodb.Client,
	redisClient *redis.Client,
	oauth2Clients []oauth2client.Client) (interface{}, error) {
	var store interface{}
	var err error

	switch transientDataStoreType {
	case redisStore:
		logger.Info("Redis oAuth store is used")
		store = fositeredis.NewStore(redisClient)
	default:
		store, err = fositemongo.NewStore(ctx, mongoClient)
		if err != nil {
			return nil, err
		}
		logger.Info("Mongo oAuth store is used")
	}

	if inserter, ok := store.(oauth2ClientStore); ok {
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
