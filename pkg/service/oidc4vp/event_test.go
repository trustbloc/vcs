/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

const (
	orgID   = "orgID"
	webHook = "webHook"
)

func TestService_SendTransactionEvent(t *testing.T) {
	txManager := NewMockTransactionManager(gomock.NewController(t))
	profileService := NewMockProfileService(gomock.NewController(t))
	mockEventSvc := NewMockeventService(gomock.NewController(t))

	tests := []struct {
		name  string
		setup func(t *testing.T)
		check func(t *testing.T, err error)
	}{
		{
			name: "Success",
			setup: func(t *testing.T) {
				txManager.EXPECT().Get(oidc4vp.TxID(transactionID)).Return(&oidc4vp.Transaction{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil)

				profileService.EXPECT().GetProfile(profileID, profileVersion).Return(&profileapi.Verifier{
					ID:             profileID,
					Version:        profileVersion,
					OrganizationID: orgID,
					WebHook:        webHook,
				}, nil)

				mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).DoAndReturn(
					expectedPublishEventFunc(t, spi.VerifierOIDCInteractionSucceeded, nil, func(t *testing.T, e *spi.Event) {
						epData, ok := e.Data.(map[string]interface{})
						assert.True(t, ok)

						assert.Equal(t, webHook, epData["webHook"])
						assert.Equal(t, orgID, epData["orgID"])
						assert.Equal(t, profileID, epData["profileID"])
						assert.Equal(t, profileVersion, epData["profileVersion"])
					}),
				)
			},
			check: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "Failure: tx manager error",
			setup: func(t *testing.T) {
				txManager.EXPECT().Get(oidc4vp.TxID(transactionID)).Return(nil, errors.New("some error"))
			},
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "get transaction: some error")
			},
		},
		{
			name: "Failure: profile svc error",
			setup: func(t *testing.T) {
				txManager.EXPECT().Get(oidc4vp.TxID(transactionID)).Return(&oidc4vp.Transaction{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil)

				profileService.EXPECT().GetProfile(profileID, profileVersion).Return(nil, errors.New("some error"))
			},
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "get profile: some error")
			},
		},
		{
			name: "Failure: send event error",
			setup: func(t *testing.T) {
				txManager.EXPECT().Get(oidc4vp.TxID(transactionID)).Return(&oidc4vp.Transaction{
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil)

				profileService.EXPECT().GetProfile(profileID, profileVersion).Return(&profileapi.Verifier{
					ID:             profileID,
					Version:        profileVersion,
					OrganizationID: orgID,
					WebHook:        webHook,
				}, nil)

				mockEventSvc.EXPECT().Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).Return(errors.New("some error"))
			},
			check: func(t *testing.T, err error) {
				assert.ErrorContains(t, err, "send tx event: some error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := oidc4vp.NewService(&oidc4vp.Config{
				TransactionManager: txManager,
				ProfileService:     profileService,
				EventSvc:           mockEventSvc,
				EventTopic:         spi.VerifierEventTopic,
			})

			tt.setup(t)

			err := s.SendTransactionEvent(context.Background(), transactionID, spi.VerifierOIDCInteractionSucceeded)

			tt.check(t, err)
		})
	}
}
