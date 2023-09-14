/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination requestobjectstore_mocks_test.go -self_package mocks -package vp -source=requestobjectstore.go -mock_names requestObjectStoreRepository=MockRequestObjectStoreRepository,eventService=MockEventService

package vp

import (
	"context"
	"net/url"
	"strings"

	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

type requestObjectStoreRepository interface {
	Create(ctx context.Context, request requestobject.RequestObject) (*requestobject.RequestObject, error)
	Find(ctx context.Context, id string) (*requestobject.RequestObject, error)
	Delete(ctx context.Context, id string) error
	GetResourceURL(key string) string
}

type RequestObjectStore struct {
	repo    requestObjectStoreRepository
	selfURI string
}

func NewRequestObjectStore(
	repo requestObjectStoreRepository,
	selfURI string,
) *RequestObjectStore {
	return &RequestObjectStore{
		repo:    repo,
		selfURI: selfURI,
	}
}

func (s *RequestObjectStore) Publish(
	ctx context.Context,
	requestObject string,
) (string, error) {
	resp, err := s.repo.Create(ctx, requestobject.RequestObject{
		Content: requestObject,
	})
	if err != nil {
		return "", err
	}

	resourceURI := s.repo.GetResourceURL(resp.ID)
	if resourceURI != "" {
		return resourceURI, nil
	}

	return url.JoinPath(s.selfURI, resp.ID)
}

func (s *RequestObjectStore) Remove(
	ctx context.Context,
	id string,
) error {
	splitResult := strings.Split(id, "/")
	lastSegment := splitResult[len(splitResult)-1]

	return s.repo.Delete(ctx, lastSegment)
}

func (s *RequestObjectStore) Get(ctx context.Context, id string) (*requestobject.RequestObject, error) {
	result, err := s.repo.Find(ctx, id)
	if err != nil {
		return nil, err
	}

	return result, nil
}
