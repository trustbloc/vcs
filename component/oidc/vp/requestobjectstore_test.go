/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		repo.EXPECT().Create(requestobject.RequestObject{
			Content: strData,
		}).Return(&requestobject.RequestObject{
			ID:      randomID,
			Content: strData,
		}, nil)

		store := NewRequestObjectStore(repo, uri)

		finalURI, err := store.Publish(string(dataBytes))

		assert.NoError(t, err)

		assert.Equal(t, fmt.Sprintf("%s/%s", uri, randomID), finalURI)
	})

	t.Run("Publish with error", func(t *testing.T) {
		errorStr := "unexpected error"

		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Create(gomock.Any()).Return(nil, errors.New(errorStr))

		store := NewRequestObjectStore(repo, uri)

		finalURI, err := store.Publish(string(dataBytes))
		assert.Empty(t, finalURI)
		assert.ErrorContains(t, err, errorStr)
	})

	t.Run("Get", func(t *testing.T) {
		id := "21342315231w"
		repo := NewMockRequestObjectStoreRepository(gomock.NewController(t))
		repo.EXPECT().Find(gomock.Any()).Return(&requestobject.RequestObject{
			ID: id,
		}, nil)

		store := NewRequestObjectStore(repo, uri)

		resp, err := store.Get(id)

		assert.NoError(t, err)
		assert.Equal(t, id, resp.ID)
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
			repo.EXPECT().Delete(testCase.expectedID).Return(nil)

			store := NewRequestObjectStore(repo, "")

			assert.NoError(t, store.Remove(testCase.path))
		})
	}
}
