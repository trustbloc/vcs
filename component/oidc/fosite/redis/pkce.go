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

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(ctx, dto.PkceSessionSegment, signature, requester, defaultTTL)
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	signatureBasedKey := resolveRedisKey(dto.PkceSessionSegment, signature)

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

func (s *Store) GetPKCERequestSession(
	ctx context.Context,
	signature string,
	session fosite.Session,
) (fosite.Requester, error) {
	return s.getSession(ctx, dto.PkceSessionSegment, signature, session)
}
