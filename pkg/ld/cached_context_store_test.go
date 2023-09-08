/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"

	"github.com/trustbloc/vcs/pkg/ld"
)

const (
	documentURL = "https://www.w3.org/2018/credentials/v1"
)

func TestCachedContextStore_Get(t *testing.T) {
	t.Run("Cache miss", func(t *testing.T) {
		rd := &jsonld.RemoteDocument{
			DocumentURL: documentURL,
		}

		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Get(documentURL).Return(nil, false).Times(1)
		mockCache.EXPECT().Set(documentURL, rd, int64(1)).Times(1)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Get(documentURL).Return(rd, nil).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		doc, err := store.Get(documentURL)
		require.NoError(t, err)
		require.NotNil(t, doc)
	})

	t.Run("Cache hit", func(t *testing.T) {
		rd := &jsonld.RemoteDocument{
			DocumentURL: documentURL,
		}

		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Get(documentURL).Return(rd, true).Times(1)
		mockCache.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Get(gomock.Any()).Times(0)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		doc, err := store.Get(documentURL)
		require.NoError(t, err)
		require.NotNil(t, doc)
	})

	t.Run("Context store error", func(t *testing.T) {
		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Get(documentURL).Return(nil, false).Times(1)
		mockCache.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Get(gomock.Any()).Return(nil, errors.New("get error")).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		doc, err := store.Get(documentURL)
		require.ErrorContains(t, err, "get error")
		require.Nil(t, doc)
	})
}

func TestCachedContextStore_Put(t *testing.T) {
	t.Run("Cache save", func(t *testing.T) {
		rd := &jsonld.RemoteDocument{
			DocumentURL: documentURL,
		}

		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Set(documentURL, rd, int64(1)).Times(1)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Put(documentURL, rd).Return(nil).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		err := store.Put(documentURL, rd)
		require.NoError(t, err)
	})

	t.Run("Context store error", func(t *testing.T) {
		rd := &jsonld.RemoteDocument{
			DocumentURL: documentURL,
		}

		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Put(documentURL, rd).Return(errors.New("put error")).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		err := store.Put(documentURL, rd)
		require.ErrorContains(t, err, "put error")
	})
}

func TestCachedContextStore_Import(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		documents := []ldcontext.Document{
			{
				URL: "https://www.w3.org/2018/credentials/v1",
			},
			{
				URL: "https://www.w3.org/2018/credentials/examples/v1",
			},
		}

		mockCache := NewMockCache(gomock.NewController(t))

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Import(documents).Return(nil).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		err := store.Import(documents)
		require.NoError(t, err)
	})

	t.Run("Failed import", func(t *testing.T) {
		documents := []ldcontext.Document{
			{
				URL: "https://www.w3.org/2018/credentials/v1",
			},
			{
				URL: "https://www.w3.org/2018/credentials/examples/v1",
			},
		}

		mockCache := NewMockCache(gomock.NewController(t))

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Import(documents).Return(errors.New("import error")).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		err := store.Import(documents)
		require.ErrorContains(t, err, "import error")
	})
}

func TestCachedContextStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		docs := []ldcontext.Document{
			{
				URL: "https://www.w3.org/2018/credentials/v1",
			},
			{
				URL: "https://www.w3.org/2018/credentials/examples/v1",
			},
		}

		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Del(docs[0].URL).Times(1)
		mockCache.EXPECT().Del(docs[1].URL).Times(1)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Delete(docs).Return(nil).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		err := store.Delete(docs)
		require.NoError(t, err)
	})

	t.Run("Failed delete", func(t *testing.T) {
		docs := []ldcontext.Document{
			{
				URL: "https://www.w3.org/2018/credentials/v1",
			},
			{
				URL: "https://www.w3.org/2018/credentials/examples/v1",
			},
		}

		mockCache := NewMockCache(gomock.NewController(t))
		mockCache.EXPECT().Del(docs[0].URL).Times(1)
		mockCache.EXPECT().Del(docs[1].URL).Times(1)

		mockContextStore := NewMockContextStore(gomock.NewController(t))
		mockContextStore.EXPECT().Delete(docs).Return(errors.New("delete error")).Times(1)

		store := ld.NewCachedContextStore(mockCache, mockContextStore)

		err := store.Delete(docs)
		require.ErrorContains(t, err, "delete error")
	})
}
