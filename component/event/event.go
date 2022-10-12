/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"encoding/json"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

// Initialize event.
func Initialize(cfg Config) (*Bus, error) {
	eventBus := NewEventBus(cfg)

	subscriber, err := NewEventSubscriber(eventBus, spi.VerifierEventTopic, handleEvent)
	if err != nil {
		return nil, err
	}

	subscriber.Start()

	return eventBus, nil
}

func handleEvent(e *spi.Event) error {
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return err
	}

	// TODO add logic to handle events needed to reach webhook

	// if event not need to reach webhook we just log it
	logger.Infof("Event: %s\n", eventBytes) //nolint: forbidigo

	return nil
}
