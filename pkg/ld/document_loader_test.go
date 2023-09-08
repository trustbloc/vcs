/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	mockldstore "github.com/trustbloc/vc-go/ld/mock"
	ldstore "github.com/trustbloc/vc-go/ld/store"

	"github.com/trustbloc/vcs/pkg/ld"
)

func TestNewDocumentLoader(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		p := &mockProvider{
			ContextStore:        mockldstore.NewMockContextStore(),
			RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
		}

		loader, err := ld.NewDocumentLoader(p)

		require.NotNil(t, loader)
		require.NoError(t, err)
	})

	t.Run("Fail to create a new document loader", func(t *testing.T) {
		p := &mockProvider{
			ContextStore:        &mockldstore.ContextStore{ErrImport: errors.New("import error")},
			RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
		}

		loader, err := ld.NewDocumentLoader(p)

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "new document loader")
	})
}

type mockProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *mockProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *mockProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}
