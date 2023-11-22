/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func TestCreateAck(t *testing.T) {
	t.Run("missing store", func(t *testing.T) {
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{})
		id, err := srv.CreateAck(context.TODO(), &oidc4ci.Ack{})
		assert.NoError(t, err)
		assert.Nil(t, id)
	})

	t.Run("success", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
		})

		item := &oidc4ci.Ack{}
		store.EXPECT().Create(gomock.Any(), item).Return("id", nil)
		id, err := srv.CreateAck(context.TODO(), item)

		assert.NoError(t, err)
		assert.Equal(t, "id", *id)
	})

	t.Run("store err", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
		})

		item := &oidc4ci.Ack{}
		store.EXPECT().Create(gomock.Any(), item).Return("", errors.New("some err"))
		id, err := srv.CreateAck(context.TODO(), item)

		assert.Nil(t, id)
		assert.ErrorContains(t, err, "some err")
	})
}

func TestAck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
			EventSvc: eventSvc,
		})

		store.EXPECT().Get(gomock.Any(), "123").Return(&oidc4ci.Ack{
			HashedToken:    "abcds",
			ProfileID:      "profile1",
			ProfileVersion: "v2.0",
			TxID:           "333",
			WebHookURL:     "444",
			OrgID:          "555",
		}, nil)
		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string, events ...*spi.Event) error {
				assert.Len(t, events, 1)
				event := events[0]

				assert.Equal(t, spi.IssuerOIDCInteractionAckFailed, event.Type)

				var dat oidc4ci.EventPayload
				assert.NoError(t, json.Unmarshal(event.Data, &dat))

				assert.Equal(t, "profile1", dat.ProfileID)
				assert.Equal(t, "v2.0", dat.ProfileVersion)
				assert.Equal(t, "555", dat.OrgID)
				assert.Equal(t, "444", dat.WebHook)
				assert.Equal(t, "wallet", dat.ErrorComponent)
				assert.Equal(t, "some-random-text", dat.Error)

				return nil
			})

		store.EXPECT().Delete(gomock.Any(), "123").Return(errors.New("ignored"))

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken: "abcds",
			Id:          "123",
			Status:      "failure",
			ErrorText:   "some-random-text",
		})
		assert.NoError(t, err)
	})

	t.Run("store err", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
			EventSvc: eventSvc,
		})

		store.EXPECT().Get(gomock.Any(), "123").Return(nil,
			errors.New("store err"))

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken: "abcds",
			Id:          "123",
		})
		assert.ErrorContains(t, err, "store err")
	})

	t.Run("invalid token", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
			EventSvc: eventSvc,
		})

		store.EXPECT().Get(gomock.Any(), "123").Return(&oidc4ci.Ack{
			HashedToken: "123",
		}, nil)

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken: "abcds",
			Id:          "123",
		})
		assert.ErrorContains(t, err, "invalid token")
	})

	t.Run("evn map", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
			EventSvc: eventSvc,
		})

		store.EXPECT().Get(gomock.Any(), "123").Return(&oidc4ci.Ack{
			HashedToken: "abcds",
		}, nil)

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken: "abcds",
			Id:          "123",
			Status:      "xxx",
		})
		assert.ErrorContains(t, err, "invalid status: xxx")
	})

	t.Run("event send err", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore: store,
			EventSvc: eventSvc,
		})

		store.EXPECT().Get(gomock.Any(), "123").Return(&oidc4ci.Ack{
			HashedToken: "abcds",
		}, nil)

		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New("event send err"))

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken: "abcds",
			Id:          "123",
			Status:      "rejected",
		})
		assert.ErrorContains(t, err, "event send err")
	})

	t.Run("test mapping", func(t *testing.T) {
		testCases := []struct {
			Input  string
			Output spi.EventType
			Error  string
		}{
			{
				Input:  "success",
				Output: spi.IssuerOIDCInteractionAckSucceeded,
			},
			{
				Input:  "failure",
				Output: spi.IssuerOIDCInteractionAckFailed,
			},
			{
				Input:  "rejected",
				Output: spi.IssuerOIDCInteractionAckRejected,
			},
			{
				Input:  "unk",
				Output: spi.IssuerOIDCInteractionAckFailed,
				Error:  "invalid status: unk",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.Input, func(t *testing.T) {
				srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{})
				event, err := srv.AckEventMap(tc.Input)
				assert.Equal(t, tc.Output, event)

				if tc.Error != "" {
					assert.ErrorContains(t, err, tc.Error)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}
