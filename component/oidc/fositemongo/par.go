package fositemongo

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (s *Store) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	mapped, ok := request.(*fosite.AuthorizeRequest)

	if !ok {
		return errors.New("expected record of type *fosite.AuthorizeRequest")
	}

	collection := s.mongoClient.Database().Collection(parCollection)
	clone := authorizeRequest{
		ResponseTypes:        mapped.ResponseTypes,
		RedirectURI:          mapped.RedirectURI,
		State:                mapped.State,
		HandledResponseTypes: mapped.HandledResponseTypes,
		ResponseMode:         mapped.ResponseMode,
		DefaultResponseMode:  mapped.DefaultResponseMode,
		ClientID:             request.GetClient().GetID(),
	}

	obj := &genericDocument[authorizeRequest]{
		ID:       primitive.ObjectID{},
		LookupID: requestURI,
		Record:   clone,
		ExpireAt: lo.ToPtr(time.Now().UTC().Add(defaultTTL)),
	}

	_, err := collection.InsertOne(ctx, obj)

	return err
}

func (s *Store) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	resp, err := getInternal[authorizeRequest](ctx, s.mongoClient, parCollection, requestURI)

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
	collection := s.mongoClient.Database().Collection(parCollection)

	_, err := collection.DeleteOne(ctx, bson.M{"_lookupId": requestURI})
	return err
}
