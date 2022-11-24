/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

// Initialize event.
func Initialize(cfg Config) (*Bus, error) {
	eventBus := NewEventBus(cfg)

	for _, topic := range []string{spi.VerifierEventTopic, spi.IssuerEventTopic} {
		subscriber, err := NewEventSubscriber(eventBus, topic, eventBus.handleEvent)

		if err != nil {
			return nil, err
		}

		subscriber.Start()
	}

	return eventBus, nil
}

type eventPayload struct {
	WebHook string `json:"webHook"`
}

func (b *Bus) handleEvent(e *spi.Event) error { //nolint:gocognit
	logger.Info("handling event", log.WithEvent(e))

	if !lo.Contains(b.getEventsToPublish(), e.Type) {
		return nil
	}

	payload := &eventPayload{}

	if err := json.Unmarshal(*e.Data, payload); err != nil {
		return err
	}

	if payload.WebHook != "" {
		req, err := json.Marshal(e)
		if err != nil {
			return err
		}

		httpClient := http.Client{Transport: &http.Transport{TLSClientConfig: b.TLSConfig}}

		//nolint:noctx
		resp, err := httpClient.Post(payload.WebHook, "application/json", bytes.NewReader(req))
		if err != nil {
			return err
		}

		defer func() {
			if errClose := resp.Body.Close(); errClose != nil {
				logger.Error("error close", log.WithError(errClose))
			}
		}()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s webhook return %d", payload.WebHook, resp.StatusCode)
		}
	}

	return nil
}

func (b *Bus) getEventsToPublish() []spi.EventType {
	return []spi.EventType{
		// oidc4vp
		spi.VerifierOIDCInteractionInitiated,
		spi.VerifierOIDCInteractionSucceeded,
		spi.VerifierOIDCInteractionQRScanned,

		// oidc4ci
		spi.IssuerOIDCInteractionInitiated,
		spi.IssuerOIDCInteractionQRScanned,
		spi.IssuerOIDCInteractionSucceeded,
		spi.IssuerOIDCInteractionAuthorizationRequestPrepared,
		spi.IssuerOIDCInteractionAuthorizationCodeStored,
		spi.IssuerOIDCInteractionAuthorizationCodeExchanged,
		spi.IssuerOIDCInteractionFailed,
	}
}
