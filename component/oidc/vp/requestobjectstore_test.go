/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/requestobject"
)

func TestRequestObjectStore(t *testing.T) {
	data := map[string]string{
		"a": "b",
	}

	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)
	strData := string(dataBytes)

	uri := "https://example.com/some/endpoint"

	t.Run("Test Publish", func(t *testing.T) {
		randomID := "2135321"

		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Create(context.TODO(), requestobject.RequestObject{
			Content:                  strData,
			AccessRequestObjectEvent: &spi.Event{},
		}).Return(&requestobject.RequestObject{
			ID:      randomID,
			Content: strData,
		}, nil)
		repo.EXPECT().GetResourceUrl(randomID).Return("")

		eventSvc := NewMockEventService(gomock.NewController(t))

		store := NewRequestObjectStore(repo, eventSvc, uri)

		finalURI, err := store.Publish(context.TODO(), string(dataBytes), &spi.Event{})

		assert.NoError(t, err)

		assert.Equal(t, fmt.Sprintf("%s/%s", uri, randomID), finalURI)
	})

	t.Run("Test Publish with RepoUrl", func(t *testing.T) {
		randomID := "2135321"

		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Create(context.TODO(), requestobject.RequestObject{
			Content:                  strData,
			AccessRequestObjectEvent: &spi.Event{},
		}).Return(&requestobject.RequestObject{
			ID:      randomID,
			Content: strData,
		}, nil)
		repo.EXPECT().GetResourceUrl(randomID).Return("https://awesome-url/resources/2135321")

		eventSvc := NewMockEventService(gomock.NewController(t))

		store := NewRequestObjectStore(repo, eventSvc, uri)

		finalURI, err := store.Publish(context.TODO(), string(dataBytes), &spi.Event{})

		assert.NoError(t, err)

		assert.Equal(t, "https://awesome-url/resources/2135321", finalURI)
	})

	t.Run("Publish with error", func(t *testing.T) {
		errorStr := "unexpected error"

		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, errors.New(errorStr))

		eventSvc := NewMockEventService(gomock.NewController(t))

		store := NewRequestObjectStore(repo, eventSvc, uri)

		finalURI, err := store.Publish(context.TODO(), string(dataBytes), &spi.Event{})
		assert.Empty(t, finalURI)
		assert.ErrorContains(t, err, errorStr)
	})

	t.Run("Get", func(t *testing.T) {
		id := "21342315231w"
		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Find(gomock.Any(), gomock.Any()).Return(&requestobject.RequestObject{
			ID: id,
		}, nil)

		eventSvc := NewMockEventService(gomock.NewController(t))
		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any()).Times(1).Return(nil)

		store := NewRequestObjectStore(repo, eventSvc, uri)

		resp, err := store.Get(context.TODO(), id)

		assert.NoError(t, err)
		assert.Equal(t, id, resp.ID)
	})

	t.Run("Get store failed", func(t *testing.T) {
		id := "21342315231w"
		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Find(gomock.Any(), gomock.Any()).Return(nil, errors.New("store failed"))

		eventSvc := NewMockEventService(gomock.NewController(t))

		store := NewRequestObjectStore(repo, eventSvc, uri)

		_, err := store.Get(context.TODO(), id)

		assert.Error(t, err)
	})

	t.Run("Get publish event failed", func(t *testing.T) {
		id := "21342315231w"
		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Find(gomock.Any(), gomock.Any()).Return(&requestobject.RequestObject{
			ID: id,
		}, nil)

		eventSvc := NewMockEventService(gomock.NewController(t))
		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any()).Times(1).Return(errors.New("publish failed"))

		store := NewRequestObjectStore(repo, eventSvc, uri)

		_, err := store.Get(context.TODO(), id)

		assert.Error(t, err)
	})
}

func TestDelete(t *testing.T) {
	cases := []struct {
		path       string
		expectedID string
	}{
		{
			path:       "https://example.com/some/endpoint/2131421312",
			expectedID: "2131421312",
		},
		{
			path:       "123456",
			expectedID: "123456",
		},
		{
			path:       "",
			expectedID: "",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.path, func(t *testing.T) {
			repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
			repo.EXPECT().Delete(gomock.Any(), testCase.expectedID).Return(nil)

			eventSvc := NewMockEventService(gomock.NewController(t))

			store := NewRequestObjectStore(repo, eventSvc, "")

			assert.NoError(t, store.Remove(context.TODO(), testCase.path))
		})
	}
}
