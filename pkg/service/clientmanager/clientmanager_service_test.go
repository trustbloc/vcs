/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/service/clientmanager"
)

func TestService_CreateClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockStore := NewMockStore(gomock.NewController(t))
		mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Return(uuid.New().String(), nil)

		svc := clientmanager.NewService(mockStore)

		oauth2Client, err := svc.CreateClient(context.Background(), &clientmanager.ClientMetadata{})
		require.NoError(t, err)
		require.NotNil(t, oauth2Client)
	})

	t.Run("store error", func(t *testing.T) {
		mockStore := NewMockStore(gomock.NewController(t))
		mockStore.EXPECT().InsertClient(gomock.Any(), gomock.Any()).Return("", errors.New("insert error"))

		svc := clientmanager.NewService(mockStore)

		oauth2Client, err := svc.CreateClient(context.Background(), &clientmanager.ClientMetadata{})
		require.ErrorContains(t, err, "insert client")
		require.Nil(t, oauth2Client)
	})
}
