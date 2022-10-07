/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"github.com/trustbloc/vcs/pkg/event/spi"
)

// NewEventPublisher creates event publisher.
func NewEventPublisher(pub eventPublisher) *Publisher {
	return &Publisher{
		publisher: pub,
	}
}

type eventPublisher interface {
	Publish(topic string, messages ...*spi.Event) error
}

type Publisher struct {
	publisher eventPublisher
}

func (p *Publisher) Publish(topic string, events ...*spi.Event) error {
	return p.publisher.Publish(topic, events...)
}
