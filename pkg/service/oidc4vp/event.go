/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.uber.org/zap"

	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
)

//nolint:funlen
func (s *Service) SendTransactionEvent(
	ctx context.Context,
	txID TxID,
	eventType spi.EventType,
) error {
	tx, err := s.transactionManager.Get(txID)
	if err != nil {
		return fmt.Errorf("get transaction: %w", err)
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		return fmt.Errorf("get profile: %w", err)
	}

	if err = s.sendTxEvent(ctx, eventType, tx, profile); err != nil {
		return fmt.Errorf("send tx event: %w", err)
	}

	return nil
}

func (s *Service) sendOIDCInteractionInitiatedEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	authorizationRequest string,
) error {
	return s.sendTxEvent(ctx, spi.VerifierOIDCInteractionInitiated, tx, profile, func(ep *EventPayload) {
		ep.AuthorizationRequest = authorizationRequest
		ep.Filter = getFilter(tx.PresentationDefinition)
	})
}

func (s *Service) sendFailedTransactionEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	e error,
) {
	err := s.sendTxEvent(ctx, spi.VerifierOIDCInteractionFailed, tx, profile, func(ep *EventPayload) {
		var oidc4vpErr *oidc4vperr.Error

		if errors.As(e, &oidc4vpErr) {
			ep.Error = oidc4vpErr.Error()
			ep.ErrorCode = oidc4vpErr.Code()
			ep.ErrorComponent = oidc4vpErr.Component()
		} else {
			ep.Error = e.Error()
		}
	})

	if err != nil {
		logger.Warnc(ctx, "Failed to send OIDC verifier event. Ignoring..", log.WithError(err))
	}
}

func (s *Service) sendOIDCInteractionSucceededEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	receivedClaims *ReceivedClaims,
	interactionDetails map[string]interface{},
) error {
	return s.sendOIDCInteractionEvent(
		ctx, tx, spi.VerifierOIDCInteractionSucceeded, profile, receivedClaims, interactionDetails)
}

func (s *Service) sendOIDCInteractionClaimsRetrievedEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	receivedClaims *ReceivedClaims,
) error {
	return s.sendOIDCInteractionEvent(
		ctx, tx, spi.VerifierOIDCInteractionClaimsRetrieved, profile, receivedClaims, nil)
}

func (s *Service) sendOIDCInteractionEvent(
	ctx context.Context,
	tx *Transaction,
	eventType spi.EventType,
	profile *profileapi.Verifier,
	receivedClaims *ReceivedClaims,
	interactionDetails map[string]interface{},
) error {
	return s.sendTxEvent(ctx, eventType, tx, profile, func(ep *EventPayload) {
		ep.InteractionDetails = interactionDetails

		for _, c := range receivedClaims.Credentials {
			cred := c.Contents()

			subjectID, err := verifiable.SubjectID(cred.Subject)
			if err != nil {
				logger.Warnc(ctx, "Unable to extract ID from credential subject: %w", log.WithError(err))
			}

			var issuerID string
			if cred.Issuer != nil {
				issuerID = cred.Issuer.ID
			}

			ep.Credentials = append(ep.Credentials, &CredentialEventPayload{
				ID:        cred.ID,
				Types:     cred.Types,
				IssuerID:  issuerID,
				SubjectID: subjectID,
			})
		}
	})
}

func (s *Service) sendWalletNotificationEvent(
	ctx context.Context,
	tx *Transaction,
	profile *profileapi.Verifier,
	notification *WalletNotification,
) error {
	// Send event only if notification.Error is known.
	if _, isValidError := supportedAuthResponseErrTypes[notification.Error]; !isValidError {
		logger.Infoc(ctx, "Ignoring unsupported error type", zap.String("error", notification.Error))
		return nil
	}

	spiEventType := s.getWalletNotificationEventType(notification.Error, notification.ErrorDescription)

	return s.sendTxEvent(ctx, spiEventType, tx, profile, func(ep *EventPayload) {
		// error code, e.g. "access_denied".
		// List: https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-7.5
		ep.ErrorCode = notification.Error

		// error description, e.g. "no_consent", "no_match_found"
		ep.Error = notification.ErrorDescription

		ep.ErrorComponent = errorComponentWallet
		ep.InteractionDetails = notification.InteractionDetails
	})
}

func (s *Service) sendTxEvent(
	ctx context.Context,
	eventType spi.EventType,
	tx *Transaction,
	profile *profileapi.Verifier,
	modifiers ...func(ep *EventPayload),
) error {
	ep := createBaseTxEventPayload(tx, profile)

	for _, modifier := range modifiers {
		modifier(ep)
	}

	event, err := CreateEvent(eventType, tx.ID, ep)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func CreateEvent(
	eventType spi.EventType,
	transactionID TxID,
	ep *EventPayload,
) (*spi.Event, error) {
	payload, err := json.Marshal(ep)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "source://vcs/verifier", eventType, payload)
	event.TransactionID = string(transactionID)

	return event, nil
}

func createBaseTxEventPayload(tx *Transaction, profile *profileapi.Verifier) *EventPayload {
	var presentationDefID string

	if tx.PresentationDefinition != nil {
		presentationDefID = tx.PresentationDefinition.ID
	}

	return &EventPayload{
		WebHook:                  profile.WebHook,
		ProfileID:                profile.ID,
		ProfileVersion:           profile.Version,
		OrgID:                    profile.OrganizationID,
		PresentationDefinitionID: presentationDefID,
	}
}
