/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
)

const (
	// VerifierEventTopic verifier topic name.
	VerifierEventTopic = "vcs-verifier"
	// IssuerEventTopic issuer topic name.
	IssuerEventTopic = "vcs-issuer"
)

// EventType event type.
type EventType string

const (
	// VerifierOIDCInteractionInitiated verifier oidc event.
	VerifierOIDCInteractionInitiated = "oidc_interaction_initiated"
	// VerifierOIDCInteractionQRScanned verifier oidc event.
	VerifierOIDCInteractionQRScanned = "oidc_interaction_qr_scanned"
	// VerifierOIDCInteractionSucceeded verifier oidc event.
	VerifierOIDCInteractionSucceeded = "oidc_interaction_succeeded"
	// VerifierOIDCInteractionFailed verifier oidc event.
	VerifierOIDCInteractionFailed = "oidc_interaction_failed"

	// IssuerOIDCInteractionInitiated Issuer oidc event.
	IssuerOIDCInteractionInitiated = EventType("oidc_interaction_initiated")
	// IssuerOIDCInteractionQRScanned Issuer oidc event.
	IssuerOIDCInteractionQRScanned = EventType("oidc_interaction_qr_scanned")
	// IssuerOIDCInteractionSucceeded Issuer oidc event.
	IssuerOIDCInteractionSucceeded                    = EventType("oidc_interaction_succeeded")
	IssuerOIDCInteractionAuthorizationRequestPrepared = EventType("oidc_interaction_authorization_request_prepared") //nolint
	IssuerOIDCInteractionAuthorizationCodeStored      = EventType("oidc_interaction_authorization_code_stored")      //nolint
	IssuerOIDCInteractionAuthorizationCodeExchanged   = EventType("oidc_interaction_authorization_code_exchanged")   //nolint
	IssuerOIDCInteractionFailed                       = EventType("oidc_interaction_failed")
)

type Payload []byte

type Event struct {
	// SpecVersion is spec version(required).
	SpecVersion string `json:"specversion"`

	// ID identifies the event(required).
	ID string `json:"id"`

	// Source is URI for producer(required).
	Source string `json:"source"`

	// Type defines event type(required).
	Type EventType `json:"type"`

	// DataContentType is data content type(required).
	DataContentType string `json:"datacontenttype"`

	// Time defines time of occurrence(required).
	Time *util.TimeWrapper `json:"time"`

	// Data defines message(required).
	Data *json.RawMessage `json:"data"`
}

// Copy an event.
func (m *Event) Copy() *Event {
	return &Event{
		SpecVersion:     m.SpecVersion,
		DataContentType: m.DataContentType,
		ID:              m.ID,
		Source:          m.Source,
		Type:            m.Type,
		Time:            m.Time,
		Data:            m.Data,
	}
}

// NewEvent creates a new Event.
func NewEvent(uuid string, source string, eventType EventType, payload Payload) *Event {
	now := time.Now()

	data := json.RawMessage(payload)

	return &Event{
		SpecVersion:     "1.0",
		DataContentType: "application/json",
		ID:              uuid,
		Source:          source,
		Type:            eventType,
		Time:            util.NewTime(now),
		Data:            &data,
	}
}

// Options contains publisher/subscriber options.
type Options struct {
	PoolSize      int
	DeliveryDelay time.Duration
}

// Option specifies a publisher/subscriber option.
type Option func(option *Options)

// WithPool sets the pool size.
func WithPool(size int) Option {
	return func(option *Options) {
		option.PoolSize = size
	}
}

// WithDeliveryDelay sets the delivery delay.
// Note: Not all message brokers support this option.
func WithDeliveryDelay(delay time.Duration) Option {
	return func(option *Options) {
		option.DeliveryDelay = delay
	}
}
