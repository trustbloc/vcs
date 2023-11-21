/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"errors"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

// CreateAck creates an acknowledgement.
func (s *Service) CreateAck(
	ctx context.Context,
	ack *Ack,
) (*string, error) {
	if s.ackStore == nil {
		return nil, nil //nolint:nilnil
	}

	id, err := s.ackStore.Create(ctx, ack)
	if err != nil {
		return nil, err
	}

	return &id, nil
}

// Ack acknowledges the interaction.
func (s *Service) Ack(
	ctx context.Context,
	id string,
	hashedToken string,
) error {
	if s.ackStore == nil {
		return nil
	}

	ack, err := s.ackStore.Get(ctx, id)
	if err != nil {
		return err
	}

	eventPayload := &EventPayload{
		WebHook:        ack.WebHookURL,
		ProfileID:      ack.ProfileID,
		ProfileVersion: ack.ProfileVersion,
		OrgID:          ack.OrgID,
	}

	if ack.HashedToken != hashedToken {
		tokenErr := errors.New("invalid token")
		s.setAckError(eventPayload, tokenErr)

		eventErr := s.sendEvent(ctx, spi.IssuerOIDCInteractionAckRejected, ack.TxID, eventPayload)
		return errors.Join(tokenErr, eventErr)
	}

	err = s.sendEvent(ctx, spi.IssuerOIDCInteractionAckSucceeded, ack.TxID, eventPayload)
	if err != nil {
		s.setAckError(eventPayload, err)
		eventErr := s.sendEvent(ctx, spi.IssuerOIDCInteractionAckFailed, ack.TxID, eventPayload)
		if eventErr != nil {
			logger.Errorc(ctx, eventErr.Error())
		}

		return errors.Join(err, eventErr)
	}

	return nil
}

func (s *Service) setAckError(payload *EventPayload, err error) {
	payload.Error = err.Error()
	payload.ErrorComponent = "ack"
}
