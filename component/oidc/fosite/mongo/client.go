/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"time"

	"github.com/ory/fosite"
)

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return s.clientManager.GetClient(ctx, id)
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return s.clientManager.ClientAssertionJWTValid(ctx, jti)
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.clientManager.SetClientAssertionJWT(ctx, jti, exp)
}
