/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"errors"

	"github.com/ory/fosite"
	"github.com/redis/go-redis/v9"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createSession(ctx, dto.AccessTokenSegment, signature, request, defaultTTL)
}

func (s *Store) GetAccessTokenSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, dto.AccessTokenSegment, signature, session)
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	signatureBasedKey := resolveRedisKey(dto.AccessTokenSegment, signature)

	intermediateKey, err := s.redisClient.API().Get(ctx, signatureBasedKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// If intermediateKey is not accessible - consider that the session is already deleted.
			return nil
		}

		return err
	}

	return s.redisClient.API().Del(ctx, intermediateKey, signatureBasedKey).Err()
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	requestIDBasedKey := resolveRedisKey(dto.AccessTokenSegment, requestID)

	intermediateKey, err := s.redisClient.API().Get(ctx, requestIDBasedKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// If intermediateKey is not accessible - consider that the session is already deleted.
			return nil
		}

		return err
	}

	return s.redisClient.API().Del(ctx, intermediateKey, requestIDBasedKey).Err()
}
