/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redis

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
)

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if id == "" { // for pre-auth we don't have client
		return &fosite.DefaultClient{}, nil
	}

	return getInternal[dto.Client](ctx, s.redisClient, dto.ClientsSegment, id)
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	_, err := getInternal[string](ctx, s.redisClient, dto.BlacklistedJTIsSegment, jti)

	if errors.Is(err, dto.ErrDataNotFound) {
		return nil
	}

	return fosite.ErrJTIKnown
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	obj := &genericDocument[string]{
		Record:   jti,
		ExpireAt: exp,
	}

	key := resolveRedisKey(dto.BlacklistedJTIsSegment, jti)

	return s.redisClient.API().Set(ctx, key, obj, exp.Sub(time.Now().UTC())).Err()
}
