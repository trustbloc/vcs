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
	"github.com/trustbloc/vcs/pkg/profile"
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
		profileSvc := NewMockProfileService(gomock.NewController(t))
		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").
			Return(&profile.Issuer{
				DataConfig: profile.IssuerDataConfig{OIDC4CIAckDataTTL: 10},
			}, nil)

		store := NewMockAckStore(gomock.NewController(t))
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			ProfileSvc: profileSvc,
			AckStore:   store,
		})

		item := &oidc4ci.Ack{
			ProfileID:      "some_issuer",
			ProfileVersion: "v1.0",
		}

		store.EXPECT().Create(gomock.Any(), int32(10), item).Return("id", nil)
		id, err := srv.CreateAck(context.TODO(), item)

		assert.NoError(t, err)
		assert.Equal(t, "id", *id)
	})

	t.Run("profile srv err", func(t *testing.T) {
		profileSvc := NewMockProfileService(gomock.NewController(t))
		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").
			Return(nil, errors.New("some error"))

		store := NewMockAckStore(gomock.NewController(t))
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			ProfileSvc: profileSvc,
		})

		item := &oidc4ci.Ack{
			ProfileID:      "some_issuer",
			ProfileVersion: "v1.0",
		}

		id, err := srv.CreateAck(context.TODO(), item)

		assert.Nil(t, id)
		assert.ErrorContains(t, err, "some error")
	})

	t.Run("store err", func(t *testing.T) {
		profileSvc := NewMockProfileService(gomock.NewController(t))
		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").
			Return(&profile.Issuer{
				DataConfig: profile.IssuerDataConfig{OIDC4CIAckDataTTL: 10},
			}, nil)

		store := NewMockAckStore(gomock.NewController(t))
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			ProfileSvc: profileSvc,
			AckStore:   store,
		})

		item := &oidc4ci.Ack{
			ProfileID:      "some_issuer",
			ProfileVersion: "v1.0",
		}
		store.EXPECT().Create(gomock.Any(), int32(10), item).Return("", errors.New("some err"))
		id, err := srv.CreateAck(context.TODO(), item)

		assert.Nil(t, id)
		assert.ErrorContains(t, err, "some err")
	})
}

func TestAckFallback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			EventSvc:   eventSvc,
			ProfileSvc: profileSvc,
		})

		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").
			Return(&profile.Issuer{
				WebHook:        "1234",
				ID:             "4567",
				Version:        "2222",
				OrganizationID: "1111",
			}, nil)

		store.EXPECT().Get(gomock.Any(), "123").Return(nil, oidc4ci.ErrDataNotFound)
		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string, events ...*spi.Event) error {
				assert.Len(t, events, 1)
				event := events[0]

				assert.Equal(t, spi.IssuerOIDCInteractionAckExpired, event.Type)

				var dat oidc4ci.EventPayload
				b, _ := json.Marshal(event.Data) //nolint
				assert.NoError(t, json.Unmarshal(b, &dat))

				assert.Equal(t, "4567", dat.ProfileID)
				assert.Equal(t, "2222", dat.ProfileVersion)
				assert.Equal(t, "1111", dat.OrgID)
				assert.Equal(t, "1234", dat.WebHook)
				assert.Equal(t, "wallet", dat.ErrorComponent)
				assert.Equal(t, "some-random-text", dat.Error)
				assert.Equal(t, map[string]interface{}{
					"key1": "value1",
				}, dat.InteractionDetails)

				return nil
			})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
			IssuerIdentifier: "https://someurl/some_issuer/v1.0",
			InteractionDetails: map[string]interface{}{
				"key1": "value1",
			},
		})
		assert.ErrorIs(t, err, oidc4ci.ErrAckExpired)
		assert.Equal(t, err.Error(), "expired_ack_id") // do not change this error code. wallet-sdk.
	})

	t.Run("success with short identifier", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			EventSvc:   eventSvc,
			ProfileSvc: profileSvc,
		})

		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").
			Return(&profile.Issuer{
				WebHook:        "1234",
				ID:             "4567",
				Version:        "2222",
				OrganizationID: "1111",
			}, nil)

		store.EXPECT().Get(gomock.Any(), "123").Return(nil, oidc4ci.ErrDataNotFound)
		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string, events ...*spi.Event) error {
				assert.Len(t, events, 1)
				event := events[0]

				assert.Equal(t, spi.IssuerOIDCInteractionAckExpired, event.Type)

				var dat oidc4ci.EventPayload
				b, _ := json.Marshal(event.Data) //nolint
				assert.NoError(t, json.Unmarshal(b, &dat))

				assert.Equal(t, "4567", dat.ProfileID)
				assert.Equal(t, "2222", dat.ProfileVersion)
				assert.Equal(t, "1111", dat.OrgID)
				assert.Equal(t, "1234", dat.WebHook)
				assert.Equal(t, "wallet", dat.ErrorComponent)
				assert.Equal(t, "some-random-text", dat.Error)
				assert.Nil(t, dat.InteractionDetails)

				return nil
			})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
			IssuerIdentifier: "some_issuer/v1.0",
		})
		assert.ErrorContains(t, err, "expired_ack_id")
	})

	t.Run("no store", func(t *testing.T) {
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
		})
		assert.NoError(t, err)
	})

	t.Run("missing identifier", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))

		store.EXPECT().Get(gomock.Any(), "123").Return(nil, oidc4ci.ErrDataNotFound)
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			EventSvc:   eventSvc,
			ProfileSvc: profileSvc,
		})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
		})
		assert.ErrorContains(t, err, "issuer identifier is empty and ack not found")
	})

	t.Run("invalid identifier", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))

		store.EXPECT().Get(gomock.Any(), "123").Return(nil, oidc4ci.ErrDataNotFound)
		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			EventSvc:   eventSvc,
			ProfileSvc: profileSvc,
		})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
			IssuerIdentifier: "abcd",
		})
		assert.ErrorContains(t, err, "invalid issuer identifier. expected format")
	})

	t.Run("profile not found", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))

		store.EXPECT().Get(gomock.Any(), "123").Return(nil, oidc4ci.ErrDataNotFound)
		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").Return(nil,
			errors.New("profile not found"))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			EventSvc:   eventSvc,
			ProfileSvc: profileSvc,
		})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
			IssuerIdentifier: "some_issuer/v1.0",
		})
		assert.ErrorContains(t, err, "profile not found")
	})

	t.Run("publish err", func(t *testing.T) {
		store := NewMockAckStore(gomock.NewController(t))
		eventSvc := NewMockEventService(gomock.NewController(t))
		profileSvc := NewMockProfileService(gomock.NewController(t))

		profileSvc.EXPECT().GetProfile("some_issuer", "v1.0").
			Return(&profile.Issuer{
				WebHook:        "1234",
				ID:             "4567",
				Version:        "2222",
				OrganizationID: "1111",
			}, nil)

		store.EXPECT().Get(gomock.Any(), "123").Return(nil, oidc4ci.ErrDataNotFound)
		eventSvc.EXPECT().Publish(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New("publish err"))

		srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{
			AckStore:   store,
			EventSvc:   eventSvc,
			ProfileSvc: profileSvc,
		})

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "failure",
			EventDescription: "some-random-text",
			IssuerIdentifier: "some_issuer/v1.0",
		})
		assert.ErrorContains(t, err, "publish err")
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
				b, _ := json.Marshal(event.Data) //nolint
				assert.NoError(t, json.Unmarshal(b, &dat))

				assert.Equal(t, "profile1", dat.ProfileID)
				assert.Equal(t, "v2.0", dat.ProfileVersion)
				assert.Equal(t, "555", dat.OrgID)
				assert.Equal(t, "444", dat.WebHook)
				assert.Equal(t, "wallet", dat.ErrorComponent)
				assert.Equal(t, "some-random-text", dat.Error)
				assert.Equal(t, map[string]interface{}{
					"key1": "value1",
				}, dat.InteractionDetails)

				return nil
			})

		store.EXPECT().Delete(gomock.Any(), "123").Return(errors.New("ignored"))

		err := srv.Ack(context.TODO(), oidc4ci.AckRemote{
			HashedToken:      "abcds",
			ID:               "123",
			Event:            "credential_failure",
			EventDescription: "some-random-text",
			InteractionDetails: map[string]interface{}{
				"key1": "value1",
			},
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
			ID:          "123",
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
			ID:          "123",
		})
		assert.ErrorContains(t, err, "invalid token")
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
			ID:          "123",
			Event:       "credential_deleted",
		})
		assert.ErrorContains(t, err, "event send err")
	})

	t.Run("test mapping", func(t *testing.T) {
		testCases := []struct {
			Input  string
			Output spi.EventType
		}{
			{
				Input:  "credential_accepted",
				Output: spi.IssuerOIDCInteractionAckSucceeded,
			},
			{
				Input:  "credential_failure",
				Output: spi.IssuerOIDCInteractionAckFailed,
			},
			{
				Input:  "credential_deleted",
				Output: spi.IssuerOIDCInteractionAckRejected,
			},
			{
				Input:  "unk",
				Output: spi.IssuerOIDCInteractionAckRejected,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.Input, func(t *testing.T) {
				srv := oidc4ci.NewAckService(&oidc4ci.AckServiceConfig{})
				event := srv.AckEventMap(tc.Input)
				assert.Equal(t, tc.Output, event)
			})
		}
	})
}
