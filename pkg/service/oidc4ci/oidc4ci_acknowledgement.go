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
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

type AckService struct {
	cfg *AckServiceConfig
}

var ErrAckExpired = errors.New("expired_ack_id")

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

// CreateAck creates an acknowledgement.
func (s *AckService) CreateAck(
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

	id, err := s.cfg.AckStore.Create(ctx, profile.DataConfig.OIDC4CIAckDataTTL, ack)
	if err != nil {
		return "", err
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
		return err
	}

	if ack.HashedToken != req.HashedToken {
		return errors.New("invalid token")
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
		return err
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
) error {
	if req.IssuerIdentifier == "" {
		return errors.New("issuer identifier is empty and ack not found")
	}

	parts := strings.Split(req.IssuerIdentifier, "/")
	if len(parts) < issuerIdentifierParts {
		return errors.New("invalid issuer identifier. expected format https://xxx/{profileID}/{profileVersion}")
	}

	profileID := parts[len(parts)-2]
	profileVersion := parts[len(parts)-1]

	profile, err := s.cfg.ProfileSvc.GetProfile(profileID, profileVersion)
	if err != nil {
		return err
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
		return err
	}

	return ErrAckExpired
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
