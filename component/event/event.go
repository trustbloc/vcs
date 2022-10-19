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

	"github.com/trustbloc/vcs/internal/pkg/log"
	"github.com/trustbloc/vcs/pkg/event/spi"
)

// Initialize event.
func Initialize(cfg Config) (*Bus, error) {
	eventBus := NewEventBus(cfg)

	subscriber, err := NewEventSubscriber(eventBus, spi.VerifierEventTopic, eventBus.handleEvent)
	if err != nil {
		return nil, err
	}

	subscriber.Start()

	return eventBus, nil
}

type eventPayload struct {
	WebHook string `json:"webHook"`
}

func (b *Bus) handleEvent(e *spi.Event) error { //nolint:gocognit
	logger.Info("handling event", log.WithEvent(e))

	//nolint:nestif
	if e.Type == spi.VerifierOIDCInteractionInitiated ||
		e.Type == spi.VerifierOIDCInteractionSucceeded ||
		e.Type == spi.VerifierOIDCInteractionQRScanned {
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
	}

	return nil
}
