/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

func TestStoreAuthCode(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))

	srv, err := oidc4vc.NewService(&oidc4vc.Config{
		TransactionStore: store,
	})
	assert.NoError(t, err)

	t.Run("update not existing opState", func(t *testing.T) {
		opState := uuid.NewString()
		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(nil, errors.New("not found"))

		resp, storeErr := srv.StoreAuthCode(context.TODO(), opState, "1234")
		assert.Empty(t, resp)
		assert.ErrorContains(t, storeErr, "not found")
	})

	t.Run("update existing", func(t *testing.T) {
		opState := uuid.NewString()
		code := uuid.NewString()

		tx := oidc4vc.Transaction{
			ID: oidc4vc.TxID(uuid.NewString()),
		}

		store.EXPECT().FindByOpState(gomock.Any(), opState).
			Return(&tx, nil)
		store.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *oidc4vc.Transaction) error {
				assert.Equal(t, tx.ID, req.ID)
				assert.Equal(t, code, req.IssuerAuthCode)

				return nil
			})

		resp, storeErr := srv.StoreAuthCode(context.TODO(), opState, code)
		assert.NoError(t, storeErr)
		assert.Equal(t, tx.ID, resp)
	})
}
