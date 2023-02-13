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
	cmdutils "github.com/trustbloc/cmdutil-go/pkg/utils/cmd"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/event/spi"
)

const (
	issuerTopicFlagName = "issuer-event-topic"
	issuerTopicEnvKey   = "VC_REST_ISSUER_EVENT_TOPIC"

	verifierTopicFlagName = "verifier-event-topic"
	verifierTopicEnvKey   = "VC_REST_VERIFIER_EVENT_TOPIC"
)

// Initialize event.
func Initialize(cfg Config) (*Bus, error) {
	eventBus := NewEventBus(cfg)

	issuerTopic := cmdutils.GetUserSetOptionalVarFromString(cfg.CMD, issuerTopicFlagName, issuerTopicEnvKey)
	if issuerTopic == "" {
		issuerTopic = spi.IssuerEventTopic
	}

	verifierTopic := cmdutils.GetUserSetOptionalVarFromString(cfg.CMD, verifierTopicFlagName, verifierTopicEnvKey)
	if verifierTopic == "" {
		verifierTopic = spi.VerifierEventTopic
	}

	issuerSubscriber, err := NewEventSubscriber(eventBus, issuerTopic, eventBus.handleEvent)
	if err != nil {
		return nil, err
	}

	verifierSubscriber, err := NewEventSubscriber(eventBus, verifierTopic, eventBus.handleEvent)
	if err != nil {
		return nil, err
	}

	issuerSubscriber.Start()
	verifierSubscriber.Start()

	return eventBus, nil
}

type eventPayload struct {
	WebHook string `json:"webHook"`
}

func (b *Bus) handleEvent(e *spi.Event) error { //nolint:gocognit
	logger.Info("handling event", logfields.WithEvent(e))

	if !lo.Contains(b.getEventsToPublish(), e.Type) {
		return nil
	}

	payload := eventPayload{}

	if err := json.Unmarshal(e.Data, &payload); err != nil {
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
