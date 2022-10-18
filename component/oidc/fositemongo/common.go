package fositemongo

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/text/language"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

func (s *Store) createSession(
	ctx context.Context,
	collectionStr string,
	lookupID string,
	requester fosite.Requester,
	ttl time.Duration,
) error {
	mapped, ok := requester.(*fosite.Request)

	if !ok {
		return errors.New("expected record of type *fosite.Request")
	}

	clone := request{
		ID:                mapped.ID,
		RequestedAt:       mapped.RequestedAt,
		RequestedScope:    mapped.RequestedScope,
		GrantedScope:      mapped.GrantedScope,
		Form:              mapped.Form,
		RequestedAudience: mapped.RequestedAudience,
		GrantedAudience:   mapped.GrantedAudience,
		Lang:              mapped.Lang,
		ClientID:          mapped.Client.GetID(),
	}

	collection := s.mongoClient.Database().Collection(collectionStr)

	obj := &genericDocument[request]{
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
	resp, err := getInternal[request](ctx, s.mongoClient, collectionStr, lookupID)

	if err != nil {
		return nil, err
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
		return nil, ErrDataNotFound
	}

	if err != nil {
		return nil, err
	}

	if doc.ExpireAt != nil && doc.ExpireAt.Before(time.Now().UTC()) {
		// due to nature of mongodb ttlIndex works every minute, so it can be a situation when we receive expired doc
		return nil, ErrDataNotFound
	}

	return &doc.Record, nil
}
