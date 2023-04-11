/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/redis/go-redis/v9"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

const intermediateKeyPrefix = "intermediate"

func (s *Store) createSession(
	ctx context.Context,
	collectionStr string,
	lookupID string,
	requester fosite.Requester,
	ttl time.Duration,
) error {
	clone := dto.Request{
		ID:                requester.GetID(),
		RequestedAt:       requester.GetRequestedAt(),
		RequestedScope:    requester.GetRequestedScopes(),
		GrantedScope:      requester.GetGrantedScopes(),
		Form:              requester.GetRequestForm(),
		RequestedAudience: requester.GetRequestedAudience(),
		GrantedAudience:   requester.GetGrantedAudience(),
		ClientID:          requester.GetClient().GetID(),
		SessionExtra:      requester.GetSession().(*fosite.DefaultSession).Extra,
	}

	switch mapped := requester.(type) {
	case *fosite.Request:
		clone.Lang = mapped.Lang
	case *fosite.AccessRequest:
		clone.Lang = mapped.Lang
	}

	obj := &genericDocument[dto.Request]{
		Record: clone,
	}

	if ttl > 0 {
		obj.ExpireAt = time.Now().UTC().Add(ttl)
	}

	lookupIDBasedKey := resolveRedisKey(collectionStr, lookupID)
	requesterIDBasedKey := resolveRedisKey(collectionStr, clone.ID)
	intermediateKey := resolveRedisKey(intermediateKeyPrefix, uuid.NewString())

	var err error
	// Set lookupIDBasedKey that points to intermediateKey
	if err = s.redisClient.Set(ctx, lookupIDBasedKey, intermediateKey, ttl).Err(); err == nil {
		// Set requesterIDBasedKey that points to intermediateKey
		if err = s.redisClient.Set(ctx, requesterIDBasedKey, intermediateKey, ttl).Err(); err == nil {
			// Set intermediateKey that points to genericDocument
			err = s.redisClient.Set(ctx, intermediateKey, obj, ttl).Err()
		}
	}

	return err
}

func (s *Store) getSession(
	ctx context.Context,
	collectionStr string,
	lookupID string,
	session fosite.Session,
) (fosite.Requester, error) {
	resp, err := getInternalIntermediateKey[dto.Request](ctx, s.redisClient, collectionStr, lookupID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	mappedSession, ok := session.(*fosite.DefaultSession)
	if !ok {
		return nil, fmt.Errorf("invalid session type: %s", reflect.TypeOf(session).String())
	}

	if mappedSession.Extra == nil {
		mappedSession.Extra = map[string]interface{}{}
	}

	for k, v := range resp.SessionExtra {
		mappedSession.Extra[k] = v
	}

	client, err := s.GetClient(ctx, resp.ClientID)
	if err != nil {
		return nil, err
	}

	return &fosite.Request{
		ID:                resp.ID,
		RequestedAt:       resp.RequestedAt,
		Client:            client,
		RequestedScope:    resp.RequestedScope,
		GrantedScope:      resp.GrantedScope,
		Form:              resp.Form,
		Session:           session,
		RequestedAudience: resp.RequestedAudience,
		GrantedAudience:   resp.GrantedAudience,
		Lang:              language.Tag{},
	}, nil
}

func getInternalIntermediateKey[T any](
	ctx context.Context,
	redisClient redis.Cmdable,
	dbCollection string,
	lookupID string,
) (*T, error) {
	lookupIDBasedKey := resolveRedisKey(dbCollection, lookupID)

	intermediateKey, err := redisClient.Get(ctx, lookupIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, dto.ErrDataNotFound
		}

		return nil, err
	}

	return get[T](ctx, redisClient, intermediateKey)
}

func getInternal[T any](
	ctx context.Context,
	redisClient redis.Cmdable,
	dbCollection string,
	lookupID string,
) (*T, error) {
	key := resolveRedisKey(dbCollection, lookupID)

	return get[T](ctx, redisClient, key)
}

func get[T any](
	ctx context.Context,
	redisClient redis.Cmdable,
	key string,
) (*T, error) {
	docBytes, err := redisClient.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, dto.ErrDataNotFound
		}

		return nil, err
	}

	var doc genericDocument[T]
	if err = json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("genericDocument unmarshal %w", err)
	}

	if !doc.ExpireAt.IsZero() && doc.ExpireAt.Before(time.Now().UTC()) {
		return nil, dto.ErrDataNotFound
	}

	return &doc.Record, nil
}

func resolveRedisKey(prefix string, lookupID string) string {
	return fmt.Sprintf("%s_%s", prefix, lookupID)
}
