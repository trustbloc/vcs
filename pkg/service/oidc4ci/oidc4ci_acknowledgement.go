/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/vcs/pkg/event/spi"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

type AckService struct {
	cfg *AckServiceConfig
}

type AckServiceConfig struct {
	AckStore   ackStore
	EventSvc   eventService
	EventTopic string
	ProfileSvc profileService
}

func NewAckService(
	cfg *AckServiceConfig,
) *AckService {
	return &AckService{
		cfg: cfg,
	}
}

// UpsertAck creates an acknowledgement if it does not exist in store, and updates in case it exists.
// Designed to be able to count amount of possible /ack request for given transaction.
func (s *AckService) UpsertAck(
	ctx context.Context,
	ack *Ack,
) (string, error) {
	if s.cfg.AckStore == nil {
		return "", nil //nolint:nilnil
	}

	profile, err := s.cfg.ProfileSvc.GetProfile(ack.ProfileID, ack.ProfileVersion)
	if err != nil {
		return "", err
	}

	// id (AKA notification_id) should be the same as txID
	// in order to be able to sent spi.IssuerOIDCInteractionAckExpired event with proper txID.
	// But, txID value might also be extracted from token.
	id := string(ack.TxID)

	var existingAck *Ack
	existingAck, err = s.cfg.AckStore.Get(ctx, id)
	if err != nil && !errors.Is(err, ErrDataNotFound) {
		return "", fmt.Errorf("get existing ack: %w", err)
	}

	// If ack is ready exists.
	if existingAck != nil {
		ack.CredentialsIssued += existingAck.CredentialsIssued

		if err = s.cfg.AckStore.Update(ctx, id, ack); err != nil { // not critical
			return "", fmt.Errorf("update ack with id[%s]: %s", id, err.Error())
		}

		return id, nil
	}

	if err = s.cfg.AckStore.Create(ctx, id, profile.DataConfig.OIDC4CIAckDataTTL, ack); err != nil {
		return "", fmt.Errorf("create ack: %w", err)
	}

	return id, nil
}

// Ack acknowledges the interaction.
func (s *AckService) Ack(
	ctx context.Context,
	req AckRemote,
) error {
	if s.cfg.AckStore == nil {
		return nil
	}

	ack, err := s.cfg.AckStore.Get(ctx, string(req.TxID))
	if err != nil {
		if errors.Is(err, ErrDataNotFound) {
			return s.handleAckNotFound(ctx, req)
		}

		return oidc4cierr.NewInvalidNotificationIDError(err)
	}

	if ack.HashedToken != req.HashedToken {
		return oidc4cierr.NewInvalidNotificationIDError(errors.New("invalid token"))
	}

	eventPayload := &EventPayload{
		WebHook:            ack.WebHookURL,
		ProfileID:          ack.ProfileID,
		ProfileVersion:     ack.ProfileVersion,
		OrgID:              ack.OrgID,
		ErrorComponent:     "wallet",
		Error:              req.EventDescription,
		ErrorCode:          req.Event,
		InteractionDetails: req.InteractionDetails,
	}

	err = s.sendEvent(ctx, s.AckEventMap(req.Event), ack.TxID, eventPayload)
	if err != nil {
		return oidc4cierr.NewInvalidNotificationRequestError(err).
			WithErrorPrefix("send request")
	}

	ack.CredentialsIssued-- // decrement counter of issued credentials.

	if ack.CredentialsIssued > 0 {
		if err = s.cfg.AckStore.Update(ctx, string(req.TxID), ack); err != nil { // not critical
			logger.Errorc(ctx, fmt.Sprintf("failed to update ack with id[%s]: %s", req.TxID, err.Error()))
		}

		return nil
	}

	if err = s.cfg.AckStore.Delete(ctx, string(req.TxID)); err != nil { // not critical
		logger.Errorc(ctx, fmt.Sprintf("failed to delete ack with id[%s]: %s", req.TxID, err.Error()))
	}

	return nil
}

func (s *AckService) handleAckNotFound(
	ctx context.Context,
	req AckRemote,
) *oidc4cierr.Error {
	if req.IssuerIdentifier == "" {
		return oidc4cierr.NewInvalidNotificationRequestError(
			errors.New("issuer identifier is empty and ack not found"))
	}

	parts := strings.Split(req.IssuerIdentifier, "/")
	if len(parts) < issuerIdentifierParts {
		return oidc4cierr.NewInvalidNotificationRequestError(
			errors.New("invalid issuer identifier. expected format https://xxx/{profileID}/{profileVersion}"))
	}

	profileID := parts[len(parts)-2]
	profileVersion := parts[len(parts)-1]

	profile, err := s.cfg.ProfileSvc.GetProfile(profileID, profileVersion)
	if err != nil {
		return oidc4cierr.NewInvalidNotificationRequestError(err).
			WithErrorPrefix("get profile")
	}

	eventPayload := &EventPayload{
		WebHook:            profile.WebHook,
		ProfileID:          profile.ID,
		ProfileVersion:     profile.Version,
		OrgID:              profile.OrganizationID,
		InteractionDetails: req.InteractionDetails,
	}

	if req.EventDescription != "" {
		eventPayload.ErrorComponent = "wallet"
		eventPayload.Error = req.EventDescription
	}

	err = s.sendEvent(ctx, spi.IssuerOIDCInteractionAckExpired, req.TxID, eventPayload)
	if err != nil {
		return oidc4cierr.NewInvalidNotificationRequestError(err).
			WithErrorPrefix("send request")
	}

	return oidc4cierr.NewExpiredAckIDError(errors.New("expired_ack_id"))
}

func (s *AckService) sendEvent(
	ctx context.Context,
	eventType spi.EventType,
	transactionID issuecredential.TxID,
	ep *EventPayload,
) error {
	event, err := createEvent(eventType, transactionID, ep)
	if err != nil {
		return err
	}

	return s.cfg.EventSvc.Publish(ctx, s.cfg.EventTopic, event)
}

func (s *AckService) AckEventMap(status string) spi.EventType {
	switch strings.ToLower(status) {
	case "credential_accepted":
		return spi.IssuerOIDCInteractionAckSucceeded
	case "credential_failure":
		return spi.IssuerOIDCInteractionAckFailed
	}

	return spi.IssuerOIDCInteractionAckRejected
}
