/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
)

const (
	// Spec: https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-6.4
	authResponseErrTypeInvalidScope            = "invalid_scope"
	authResponseErrTypeInvalidRequest          = "invalid_request"
	authResponseErrTypeInvalidClient           = "invalid_client"
	authResponseErrTypeAccessDenied            = "access_denied"
	authResponseErrTypeVPFormatsNotSupported   = "vp_formats_not_supported"
	authResponseErrTypeInvalidPDURI            = "invalid_presentation_definition_uri"
	authResponseErrTypeInvalidPDReference      = "invalid_presentation_definition_reference"
	authResponseErrTypeInvalidRequestURIMethod = "invalid_request_uri_method"
	authResponseErrTypeWalletUnavailable       = "wallet_unavailable"

	errorComponentWallet = "wallet"

	errorDescriptionNoConsent    = "no_consent"
	errorDescriptionNoMatchFound = "no_match_found"
)

var supportedAuthResponseErrTypes = map[string]struct{}{ //nolint:gochecknoglobals
	authResponseErrTypeInvalidScope:            {},
	authResponseErrTypeInvalidRequest:          {},
	authResponseErrTypeInvalidClient:           {},
	authResponseErrTypeAccessDenied:            {},
	authResponseErrTypeVPFormatsNotSupported:   {},
	authResponseErrTypeInvalidPDURI:            {},
	authResponseErrTypeInvalidPDReference:      {},
	authResponseErrTypeInvalidRequestURIMethod: {},
	authResponseErrTypeWalletUnavailable:       {},
}

// HandleWalletNotification handles wallet notifications.
func (s *Service) HandleWalletNotification(ctx context.Context, req *WalletNotification) error { // *oidc4vperr.Error
	tx, err := s.transactionManager.Get(req.TxID)
	if err != nil {
		if errors.Is(err, ErrDataNotFound) {
			if err = s.handleAckNotFound(ctx, req); err != nil {
				return oidc4vperr.NewBadRequestError(err)
			}

			return nil
		}

		return oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierTxnMgrComponent).
			WithOperation("get-txn").
			WithErrorPrefix("fail to get oidc tx")
	}

	profile, err := s.profileService.GetProfile(tx.ProfileID, tx.ProfileVersion)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			err = fmt.Errorf(
				"profile with given id %s_%s, doesn't exist", tx.ProfileID, tx.ProfileVersion)
		}

		return oidc4vperr.
			NewBadRequestError(err).
			WithComponent(resterr.VerifierProfileSvcComponent).
			WithOperation("GetProfile")
	}

	if err = s.sendWalletNotificationEvent(ctx, tx, profile, req); err != nil {
		return oidc4vperr.NewBadRequestError(err).
			WithErrorPrefix("send wallet notification event")
	}

	// Delete tx from store.
	err = s.transactionManager.Delete(req.TxID)
	if err != nil {
		return oidc4vperr.NewBadRequestError(err).
			WithComponent(resterr.VerifierTxnMgrComponent).
			WithOperation("delete")
	}

	return nil
}

func (s *Service) handleAckNotFound(ctx context.Context, ackData *WalletNotification) error {
	eventPayload := &EventPayload{
		Error:              ackData.ErrorDescription,
		ErrorCode:          ackData.Error,
		ErrorComponent:     errorComponentWallet,
		InteractionDetails: ackData.InteractionDetails,
	}

	event, err := CreateEvent(spi.VerifierOIDCInteractionExpired, ackData.TxID, eventPayload)
	if err != nil {
		return err
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
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

	ep := createBaseTxEventPayload(tx, profile)

	// error code, e.g. "access_denied".
	// List: https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-7.5
	ep.ErrorCode = notification.Error

	// error description, e.g. "no_consent", "no_match_found"
	ep.Error = notification.ErrorDescription

	ep.ErrorComponent = errorComponentWallet
	ep.InteractionDetails = notification.InteractionDetails

	spiEventType := s.getEventType(notification.Error, notification.ErrorDescription)

	event, e := CreateEvent(spiEventType, tx.ID, ep)
	if e != nil {
		return e
	}

	return s.eventSvc.Publish(ctx, s.eventTopic, event)
}

func (s *Service) getEventType(e, errorDescription string) spi.EventType {
	if strings.ToLower(e) == authResponseErrTypeAccessDenied {
		switch strings.ToLower(errorDescription) {
		case errorDescriptionNoConsent:
			return spi.VerifierOIDCInteractionNoConsent
		case errorDescriptionNoMatchFound:
			return spi.VerifierOIDCInteractionNoMatchFound
		}
	}

	return spi.VerifierOIDCInteractionFailed
}
