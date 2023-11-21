/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestCreateAck(t *testing.T) {
	t.Run("missing store", func(t *testing.T) {
		srv, err := oidc4ci.NewService(&oidc4ci.Config{})
		assert.NoError(t, err)
		id, err := srv.CreateAck(context.TODO(), &oidc4ci.Ack{})
		assert.NoError(t, err)
		assert.Nil(t, id)
	})

	t.Run("success", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			AckStore: store,
		})
		assert.NoError(t, err)

		item := &oidc4ci.Ack{}
		store.EXPECT().Create(gomock.Any(), item).Return("id", nil)
		id, err := srv.CreateAck(context.TODO(), item)

		assert.NoError(t, err)
		assert.Equal(t, "id", *id)
	})

	t.Run("store err", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		srv, err := oidc4ci.NewService(&oidc4ci.Config{
			AckStore: store,
		})
		assert.NoError(t, err)

		item := &oidc4ci.Ack{}
		store.EXPECT().Create(gomock.Any(), item).Return("", errors.New("some err"))
		id, err := srv.CreateAck(context.TODO(), item)

		assert.Nil(t, id)
		assert.ErrorContains(t, err, "some err")
	})
}

func TestAck(t *testing.T) {

}
