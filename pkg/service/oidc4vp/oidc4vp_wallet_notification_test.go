package oidc4vp_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
	"github.com/trustbloc/vcs/pkg/service/oidc4vp"
)

func TestService_HandleWalletNotification_SupportedAuthResponseErrorTypes(t *testing.T) {
	var (
		ctx                = context.Background()
		transactionManager = NewMockTransactionManager(gomock.NewController(t))
		profileService     = NewMockProfileService(gomock.NewController(t))
		eventService       = NewMockeventService(gomock.NewController(t))

		transactionID      = oidc4vp.TxID(uuid.NewString())
		profileOrgID       = uuid.NewString()
		profileWebHook     = "https://example/com/webhook"
		interactionDetails = map[string]interface{}{
			"key1": "value1",
		}
	)

	tests := []struct {
		Error              string
		ErrorDescription   string
		ExpectedEventType  spi.EventType
		InteractionDetails map[string]interface{}
	}{
		{
			Error:              "invalid_scope",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "invalid_request",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "invalid_client",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "access_denied",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "access_denied",
			ErrorDescription:   "no_consent",
			ExpectedEventType:  spi.VerifierOIDCInteractionNoConsent,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "access_denied",
			ErrorDescription:   "no_match_found",
			ExpectedEventType:  spi.VerifierOIDCInteractionNoMatchFound,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "vp_formats_not_supported",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "invalid_presentation_definition_uri",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "invalid_presentation_definition_reference",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "invalid_request_uri_method",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
		{
			Error:              "wallet_unavailable",
			ErrorDescription:   "error description",
			ExpectedEventType:  spi.VerifierOIDCInteractionFailed,
			InteractionDetails: interactionDetails,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Success: %s error type", tt.Error), func(t *testing.T) {
			transactionManager.EXPECT().
				Get(transactionID).Times(1).
				Return(&oidc4vp.Transaction{
					ID:             transactionID,
					ProfileID:      profileID,
					ProfileVersion: profileVersion,
				}, nil)

			profileService.EXPECT().
				GetProfile(profileID, profileVersion).
				Return(&profileapi.Verifier{
					ID:             profileID,
					Version:        profileVersion,
					OrganizationID: profileOrgID,
					WebHook:        profileWebHook,
				}, nil)

			eventService.EXPECT().
				Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).
				DoAndReturn(func(_ context.Context, _ string, evtArr ...*spi.Event) error {
					evt := evtArr[0]

					assert.NotEmpty(t, evt.ID)
					assert.Equal(t, "source://vcs/verifier", evt.Source)
					assert.Equal(t, string(transactionID), evt.TransactionID)
					assert.Equal(t, tt.ExpectedEventType, evt.Type)

					assert.Equal(t, map[string]interface{}{
						"webHook":             "https://example/com/webhook",
						"profileID":           profileID,
						"profileVersion":      profileVersion,
						"orgID":               profileOrgID,
						"error":               tt.ErrorDescription,
						"errorCode":           tt.Error,
						"errorComponent":      "wallet",
						"interaction_details": interactionDetails,
					}, evt.Data)

					return nil
				})

			transactionManager.EXPECT().
				Delete(transactionID).Times(1).
				Return(nil)

			s := oidc4vp.NewService(&oidc4vp.Config{
				EventSvc:           eventService,
				EventTopic:         spi.VerifierEventTopic,
				TransactionManager: transactionManager,
				ProfileService:     profileService,
			})

			err := s.HandleWalletNotification(ctx, &oidc4vp.WalletNotification{
				TxID:               transactionID,
				Error:              tt.Error,
				ErrorDescription:   tt.ErrorDescription,
				InteractionDetails: tt.InteractionDetails,
			})

			assert.NoError(t, err)
		})
	}
}

func TestService_HandleWalletNotification_EdgeCases(t *testing.T) {
	var (
		ctx                = context.Background()
		transactionManager = NewMockTransactionManager(gomock.NewController(t))
		profileService     = NewMockProfileService(gomock.NewController(t))
		eventService       = NewMockeventService(gomock.NewController(t))

		transactionID  = oidc4vp.TxID(uuid.NewString())
		profileOrgID   = uuid.NewString()
		profileWebHook = "https://example/com/webhook"
	)

	type fields struct {
		setup func()
		check func(t *testing.T, err error)
	}
	tests := []struct {
		name         string
		fields       fields
		notification *oidc4vp.WalletNotification
	}{
		{
			name: "Success: failed to get transaction: not found",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(nil, oidc4vp.ErrDataNotFound)

					eventService.EXPECT().
						Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).
						DoAndReturn(func(_ context.Context, _ string, evtArr ...*spi.Event) error {
							evt := evtArr[0]

							assert.NotEmpty(t, evt.ID)
							assert.Equal(t, "source://vcs/verifier", evt.Source)
							assert.Equal(t, string(transactionID), evt.TransactionID)
							assert.Equal(t, spi.VerifierOIDCInteractionExpired, evt.Type)

							assert.Equal(t, map[string]interface{}{
								"errorCode":      "invalid_scope",
								"errorComponent": "wallet",
								"error":          "error description",
								"interaction_details": map[string]interface{}{
									"key1": "value1",
								},
							}, evt.Data)

							return nil
						})
				},
				check: func(t *testing.T, err error) {
					assert.NoError(t, err)
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID:             transactionID,
				Error:            "invalid_scope",
				ErrorDescription: "error description",
				InteractionDetails: map[string]interface{}{
					"key1": "value1",
				},
			},
		},
		{
			name: "Success: unsupported error type",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(&oidc4vp.Transaction{
							ID:             transactionID,
							ProfileID:      profileID,
							ProfileVersion: profileVersion,
						}, nil)

					profileService.EXPECT().
						GetProfile(profileID, profileVersion).
						Return(&profileapi.Verifier{
							ID:             profileID,
							Version:        profileVersion,
							OrganizationID: profileOrgID,
							WebHook:        profileWebHook,
						}, nil)

					transactionManager.EXPECT().
						Delete(transactionID).Times(1).
						Return(nil)
				},
				check: func(t *testing.T, err error) {
					assert.NoError(t, err)
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID:  transactionID,
				Error: uuid.NewString(),
			},
		},
		{
			name: "Error: failed to get transaction",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(nil, errors.New("some error"))
				},
				check: func(t *testing.T, err error) {
					var sysError *oidc4vperr.Error

					assert.ErrorAs(t, err, &sysError)
					assert.Equal(t, sysError.ErrorComponent, resterr.VerifierTxnMgrComponent)
					assert.Equal(t, sysError.Operation, "get-txn")
					assert.ErrorContains(t, sysError.Err, "fail to get oidc tx")
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID: transactionID,
			},
		},
		{
			name: "Error: failed to get transaction: not found: failed to publish event",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(nil, oidc4vp.ErrDataNotFound)

					eventService.EXPECT().
						Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).
						Return(errors.New("event service error"))
				},
				check: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "event service error")
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID:             transactionID,
				Error:            "invalid_scope",
				ErrorDescription: "error description",
			},
		},
		{
			name: "Error: profile not found",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(&oidc4vp.Transaction{
							ID:             transactionID,
							ProfileID:      profileID,
							ProfileVersion: profileVersion,
						}, nil)

					profileService.EXPECT().
						GetProfile(profileID, profileVersion).
						Return(nil, errors.New("not found"))
				},
				check: func(t *testing.T, err error) {
					var sysError *oidc4vperr.Error

					assert.ErrorAs(t, err, &sysError)
					assert.Equal(t, sysError.Code(), "bad_request")
					assert.ErrorContains(t,
						sysError.Err,
						fmt.Sprintf("profile with given id %s_%s, doesn't exist", profileID, profileVersion))
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID: transactionID,
			},
		},
		{
			name: "Error: profile service error",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(&oidc4vp.Transaction{
							ID:             transactionID,
							ProfileID:      profileID,
							ProfileVersion: profileVersion,
						}, nil)

					profileService.EXPECT().
						GetProfile(profileID, profileVersion).
						Return(nil, errors.New("some error"))
				},
				check: func(t *testing.T, err error) {
					var sysError *oidc4vperr.Error

					assert.ErrorAs(t, err, &sysError)
					assert.Equal(t, sysError.ErrorComponent, resterr.VerifierProfileSvcComponent)
					assert.Equal(t, sysError.Operation, "GetProfile")
					assert.ErrorContains(t, sysError.Err, "some error")
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID: transactionID,
			},
		},
		{
			name: "Error: failed to publish event",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(&oidc4vp.Transaction{
							ID:             transactionID,
							ProfileID:      profileID,
							ProfileVersion: profileVersion,
						}, nil)

					profileService.EXPECT().
						GetProfile(profileID, profileVersion).
						Return(&profileapi.Verifier{
							ID:             profileID,
							Version:        profileVersion,
							OrganizationID: profileOrgID,
							WebHook:        profileWebHook,
						}, nil)

					eventService.EXPECT().
						Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).
						Return(errors.New("event service error"))
				},
				check: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "event service error")
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID:             transactionID,
				Error:            "invalid_scope",
				ErrorDescription: "error description",
			},
		},
		{
			name: "Error: failed to delete transaction",
			fields: fields{
				setup: func() {
					transactionManager.EXPECT().
						Get(transactionID).Times(1).
						Return(&oidc4vp.Transaction{
							ID:             transactionID,
							ProfileID:      profileID,
							ProfileVersion: profileVersion,
						}, nil)

					profileService.EXPECT().
						GetProfile(profileID, profileVersion).
						Return(&profileapi.Verifier{
							ID:             profileID,
							Version:        profileVersion,
							OrganizationID: profileOrgID,
							WebHook:        profileWebHook,
						}, nil)

					eventService.EXPECT().
						Publish(gomock.Any(), spi.VerifierEventTopic, gomock.Any()).
						Return(nil)

					transactionManager.EXPECT().
						Delete(transactionID).Times(1).
						Return(errors.New("transaction service error"))
				},
				check: func(t *testing.T, err error) {
					assert.ErrorContains(t, err, "transaction service error")
				},
			},
			notification: &oidc4vp.WalletNotification{
				TxID:             transactionID,
				Error:            "invalid_scope",
				ErrorDescription: "error description",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fields.setup()

			s := oidc4vp.NewService(&oidc4vp.Config{
				EventSvc:           eventService,
				EventTopic:         spi.VerifierEventTopic,
				TransactionManager: transactionManager,
				ProfileService:     profileService,
			})

			err := s.HandleWalletNotification(ctx, tt.notification)

			tt.fields.check(t, err)
		})
	}
}
