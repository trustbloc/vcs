/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	cmdutils "github.com/trustbloc/cmdutil-go/pkg/utils/cmd"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/event/spi"
	credentialstatustracing "github.com/trustbloc/vcs/pkg/observability/tracing/wrappers/credentialstatus/eventhandler"
	credentialstatuseventhandler "github.com/trustbloc/vcs/pkg/service/credentialstatus/eventhandler"
)

const (
	issuerTopicFlagName = "issuer-event-topic"
	issuerTopicEnvKey   = "VC_REST_ISSUER_EVENT_TOPIC"

	verifierTopicFlagName = "verifier-event-topic"
	verifierTopicEnvKey   = "VC_REST_VERIFIER_EVENT_TOPIC"

	credentialstatusTopicFlagName = "credentialstatus-event-topic"
	credentialstatusTopicEnvKey   = "VC_REST_CREDENTIALSTATUS_EVENT_TOPIC" //nolint:gosec
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

	credentialStatusTopic := cmdutils.GetUserSetOptionalVarFromString(
		cfg.CMD, credentialstatusTopicFlagName, credentialstatusTopicEnvKey)
	if credentialStatusTopic == "" {
		credentialStatusTopic = spi.CredentialStatusEventTopic
	}

	issuerSubscriber, err := NewEventSubscriber(eventBus, issuerTopic, eventBus.handleEvent)
	if err != nil {
		return nil, err
	}

	verifierSubscriber, err := NewEventSubscriber(eventBus, verifierTopic, eventBus.handleEvent)
	if err != nil {
		return nil, err
	}

	service := credentialstatuseventhandler.New(&credentialstatuseventhandler.Config{
		CSLVCStore:     cfg.CSLVCStore,
		ProfileService: cfg.ProfileService,
		KMSRegistry:    cfg.KMSRegistry,
		Crypto:         cfg.Crypto,
		DocumentLoader: cfg.DocumentLoader,
	})

	var credentialStatusEventHandler eventHandlerWithContext = service.HandleEvent
	if cfg.IsTraceEnabled {
		credentialStatusEventHandler = credentialstatustracing.Wrap(service, cfg.Tracer).HandleEvent
	}

	credentialStatusSubscriber, err := NewEventSubscriber(eventBus, credentialStatusTopic,
		func(event *spi.Event) error { return credentialStatusEventHandler(context.Background(), event) })
	if err != nil {
		return nil, err
	}

	issuerSubscriber.Start()
	verifierSubscriber.Start()
	credentialStatusSubscriber.Start()

	return eventBus, nil
}

type eventPayload struct {
	WebHook string `json:"webHook"`
}

func (b *Bus) handleEvent(e *spi.Event) error { //nolint:gocognit
	logger.Info("handling event", logfields.WithEvent(e))

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
