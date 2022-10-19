/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination requestobjectstore_mocks_test.go -self_package mocks -package vp -source=requestobjectstore.go -mock_names requestObjectStoreRepository=MockRequestObjectStoreRepository,eventService=MockEventService

package vp

import (
	"net/url"
	"strings"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

type requestObjectStoreRepository interface {
	Create(request requestobject.RequestObject) (*requestobject.RequestObject, error)
	Find(id string) (*requestobject.RequestObject, error)
	Delete(id string) error
}

type eventService interface {
	Publish(topic string, messages ...*spi.Event) error
}

type RequestObjectStore struct {
	repo     requestObjectStoreRepository
	eventSvc eventService

	selfURI string
}

func NewRequestObjectStore(
	repo requestObjectStoreRepository,
	eventSvc eventService,
	selfURI string,
) *RequestObjectStore {
	return &RequestObjectStore{
		repo:     repo,
		eventSvc: eventSvc,
		selfURI:  selfURI,
	}
}

func (s *RequestObjectStore) Publish(requestObject string, accessRequestObjectEvent *spi.Event) (string, error) {
	resp, err := s.repo.Create(requestobject.RequestObject{
		Content:                  requestObject,
		AccessRequestObjectEvent: accessRequestObjectEvent,
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
	result, err := s.repo.Find(id)
	if err != nil {
		return nil, err
	}

	err = s.eventSvc.Publish(spi.VerifierEventTopic, result.AccessRequestObjectEvent)
	if err != nil {
		return nil, err
	}

	return result, nil
}
