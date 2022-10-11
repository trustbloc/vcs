/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination requestobjectstore_mock.go -self_package mocks -package vp -source=requestobjectstore.go -mock_names requestObjectStoreRepository=MockRequestObjectStoreRepository

package vp

import (
	"net/url"
	"strings"

	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

type requestObjectStoreRepository interface {
	Create(request requestobject.RequestObject) (*requestobject.RequestObject, error)
	Find(id string) (*requestobject.RequestObject, error)
	Delete(id string) error
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

func (s *RequestObjectStore) Publish(requestObject string) (string, error) {
	resp, err := s.repo.Create(requestobject.RequestObject{
		Content: requestObject,
	})

	if err != nil {
		return "", err
	}

	return url.JoinPath(s.selfURI, resp.ID)
}

func (s *RequestObjectStore) Remove(id string) error {
	splitResult := strings.Split(id, "/")
	lastSegment := splitResult[len(splitResult)-1]

	return s.repo.Delete(lastSegment)
}

func (s *RequestObjectStore) Get(id string) (*requestobject.RequestObject, error) {
	return s.repo.Find(id)
}
