/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package event

import (
	"context"

	"github.com/trustbloc/vcs/pkg/event/spi"
)

// NewEventPublisher creates event publisher.
func NewEventPublisher(pub eventPublisher) *Publisher {
	return &Publisher{
		publisher: pub,
	}
}

type eventPublisher interface {
	Publish(ctx context.Context, topic string, events ...*spi.Event) error
}

type Publisher struct {
	publisher eventPublisher
}

func (p *Publisher) Publish(ctx context.Context, topic string, events ...*spi.Event) error {
	return p.publisher.Publish(ctx, topic, events...)
}
