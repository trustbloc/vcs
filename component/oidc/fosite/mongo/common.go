/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/ory/fosite"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/component/oidc/fosite/dto"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

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
		SessionExtra:      requester.GetSession().(*fosite.DefaultSession).Extra, // nolint:errcheck
	}

	switch mapped := requester.(type) {
	case *fosite.Request:
		clone.Lang = mapped.Lang
	case *fosite.AccessRequest:
		clone.Lang = mapped.Lang
	}

	collection := s.mongoClient.Database().Collection(collectionStr)

	obj := &genericDocument[dto.Request]{
		ID:       primitive.ObjectID{},
		LookupID: lookupID,
		Record:   clone,
	}

	if ttl > 0 {
		obj.ExpireAt = lo.ToPtr(time.Now().UTC().Add(ttl))
	}

	_, err := collection.InsertOne(ctx, obj)

	return err
}

func (s *Store) getSession(
	ctx context.Context,
	collectionStr string,
	lookupID string,
	session fosite.Session,
) (fosite.Requester, error) {
	resp, err := getInternal[dto.Request](ctx, s.mongoClient, collectionStr, lookupID)
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

func getInternal[T any](
	ctx context.Context,
	mongoClient *mongodb.Client,
	dbCollection string,
	lookupID string,
) (*T, error) {
	var doc genericDocument[T]
	collection := mongoClient.Database().Collection(dbCollection)

	err := collection.FindOne(ctx, bson.M{"_lookupId": lookupID}).Decode(&doc)

	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, dto.ErrDataNotFound
	}

	if err != nil {
		return nil, err
	}

	if doc.ExpireAt != nil && doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, dto.ErrDataNotFound
	}

	return &doc.Record, nil
}
