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

func (s *Store) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	mapped, ok := request.(*fosite.AuthorizeRequest)

	if !ok {
		return errors.New("expected record of type *fosite.AuthorizeRequest")
	}

	clone := dto.AuthorizeRequest{
		ResponseTypes:        mapped.ResponseTypes,
		RedirectURI:          mapped.RedirectURI,
		State:                mapped.State,
		HandledResponseTypes: mapped.HandledResponseTypes,
		ResponseMode:         mapped.ResponseMode,
		DefaultResponseMode:  mapped.DefaultResponseMode,
		ClientID:             request.GetClient().GetID(),
	}

	obj := &genericDocument[dto.AuthorizeRequest]{
		Record:   clone,
		ExpireAt: time.Now().UTC().Add(defaultTTL),
	}

	key := resolveRedisKey(dto.ParSegment, requestURI)

	return s.redisClient.API().Set(ctx, key, obj, defaultTTL).Err()
}

func (s *Store) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	resp, err := getInternal[dto.AuthorizeRequest](ctx, s.redisClient, dto.ParSegment, requestURI)

	if err != nil {
		return nil, err
	}

	client, err := s.GetClient(ctx, resp.ClientID)

	if err != nil {
		return nil, err
	}

	return &fosite.AuthorizeRequest{
		ResponseTypes:        resp.ResponseTypes,
		RedirectURI:          resp.RedirectURI,
		State:                resp.State,
		HandledResponseTypes: resp.HandledResponseTypes,
		ResponseMode:         resp.ResponseMode,
		DefaultResponseMode:  resp.DefaultResponseMode,
		Request: fosite.Request{
			Client: client,
		},
	}, nil
}

func (s *Store) DeletePARSession(ctx context.Context, requestURI string) error {
	key := resolveRedisKey(dto.ParSegment, requestURI)

	return s.redisClient.API().Del(ctx, key).Err()
}
