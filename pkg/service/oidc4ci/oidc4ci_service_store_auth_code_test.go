/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestStoreAuthCode(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	eventMock := NewMockEventService(gomock.NewController(t))

	srv, err := oidc4ci.NewService(&oidc4ci.Config{
		TransactionStore: store,
		EventService:     eventMock,
		EventTopic:       spi.IssuerEventTopic,
	})
	assert.NoError(t, err)

	t.Run("update not existing opState", func(t *testing.T) {
		opState := uuid.NewString()
		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(nil, errors.New("not found"))

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, "1234")
		assert.Empty(t, resp)
		assert.ErrorContains(t, storeErr, "not found")
	})

	t.Run("publish error", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4ci.Transaction{
			ID: oidc4ci.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4ci.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return errors.New("update error")
			})

		eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

				return nil
			})

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, code)
		assert.ErrorContains(t, storeErr, "update error")
		assert.NotEqual(t, tx.ID, resp)
	})

	t.Run("update existing", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4ci.Transaction{
			ID: oidc4ci.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4ci.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return nil
			})

		eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationCodeStored)

				return nil
			})

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, code)
		assert.NoError(t, storeErr)
		assert.Equal(t, tx.ID, resp)
	})

	t.Run("update existing with publish error", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4ci.Transaction{
			ID: oidc4ci.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4ci.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return nil
			})

		eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionAuthorizationCodeStored)

				return errors.New("publish error")
			})

		eventMock.EXPECT().Publish(spi.IssuerEventTopic, gomock.Any()).
			DoAndReturn(func(topic string, messages ...*spi.Event) error {
				assert.Len(t, messages, 1)
				assert.Equal(t, messages[0].Type, spi.IssuerOIDCInteractionFailed)

				return nil
			})

		resp, storeErr := srv.StoreAuthorizationCode(context.TODO(), opState, code)
		assert.ErrorContains(t, storeErr, "publish error")
		assert.NotEqual(t, tx.ID, resp)
	})
}
