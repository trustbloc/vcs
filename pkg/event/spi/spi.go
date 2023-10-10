/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"time"

	utiltime "github.com/trustbloc/did-go/doc/util/time"
)

const (
	// VerifierEventTopic verifier topic name.
	VerifierEventTopic = "vcs-verifier"
	// IssuerEventTopic issuer topic name.
	IssuerEventTopic = "vcs-issuer"
	// CredentialStatusEventTopic credential status topic name.
	CredentialStatusEventTopic = "vcs-credentialstatus"
)

// EventType event type.
type EventType string

const (
	// VerifierOIDCInteractionInitiated verifier oidc event.
	VerifierOIDCInteractionInitiated = "verifier.oidc-interaction-initiated.v1"
	// VerifierOIDCInteractionQRScanned verifier oidc event.
	VerifierOIDCInteractionQRScanned = "verifier.oidc-interaction-qr-scanned.v1"
	// VerifierOIDCInteractionSucceeded verifier oidc event.
	VerifierOIDCInteractionSucceeded = "verifier.oidc-interaction-succeeded.v1"
	// VerifierOIDCInteractionFailed verifier oidc event.
	VerifierOIDCInteractionFailed = "verifier.oidc-interaction-failed.v1"

	// IssuerOIDCInteractionInitiated Issuer oidc event.
	IssuerOIDCInteractionInitiated = EventType("issuer.oidc-interaction-initiated.v1")
	// IssuerOIDCInteractionQRScanned Issuer oidc event.
	IssuerOIDCInteractionQRScanned = EventType("issuer.oidc-interaction-qr-scanned.v1")
	// IssuerOIDCInteractionSucceeded Issuer oidc event.
	IssuerOIDCInteractionSucceeded                    = EventType("issuer.oidc-interaction-succeeded.v1")
	IssuerOIDCInteractionAuthorizationRequestPrepared = EventType("issuer.oidc-interaction-authorization-request-prepared.v1") //nolint
	IssuerOIDCInteractionAuthorizationCodeStored      = EventType("issuer.oidc-interaction-authorization-code-stored.v1")      //nolint
	IssuerOIDCInteractionAuthorizationCodeExchanged   = EventType("issuer.oidc-interaction-authorization-code-exchanged.v1")   //nolint
	IssuerOIDCInteractionFailed                       = EventType("issuer.oidc-interaction-failed.v1")

	CredentialStatusStatusUpdated = EventType("issuer.credential-status-updated.v1")
)

// Payload defines payload.
type Payload []byte

// Event defines event.
type Event struct {
	// SpecVersion is spec version(required).
	SpecVersion string `json:"specversion"`

	// ID identifies the event(required).
	ID string `json:"id"`

	// Source is URI for producer(required).
	Source string `json:"source"`

	// Type defines event type(required).
	Type EventType `json:"type"`

	// Time defines time of occurrence(required).
	Time *utiltime.TimeWrapper `json:"time"`

	// DataContentType is data content type(optional).
	DataContentType string `json:"datacontenttype,omitempty"`

	// Data defines message(optional).
	Data []byte `json:"data,omitempty"`

	// TransactionID defines transaction ID(optional).
	TransactionID string `json:"txnid,omitempty"`

	// Subject defines subject(optional).
	Subject string `json:"subject,omitempty"`

	// Tracing defines tracing information(optional).
	Tracing string `json:"tracing,omitempty"`

	// RoutingKey is an optional key that is used by the event bus to determining how/where to route the event.
	RoutingKey string `json:"-"`
}

// Copy an event.
func (m *Event) Copy() *Event {
	return &Event{
		SpecVersion:     m.SpecVersion,
		ID:              m.ID,
		Source:          m.Source,
		Type:            m.Type,
		Time:            m.Time,
		DataContentType: m.DataContentType,
		Data:            m.Data,
		TransactionID:   m.TransactionID,
		Subject:         m.Subject,
		Tracing:         m.Tracing,
	}
}

// NewEventWithPayload creates a new Event with payload.
func NewEventWithPayload(uuid string, source string, eventType EventType, payload Payload) *Event {
	event := NewEvent(uuid, source, eventType)

	event.Data = payload

	// vcs components always use json
	event.DataContentType = "application/json"

	return event
}

// NewEvent creates a new Event and sets all required fields.
func NewEvent(uuid string, source string, eventType EventType) *Event {
	now := time.Now()

	return &Event{
		SpecVersion: "1.0",
		ID:          uuid,
		Source:      source,
		Type:        eventType,
		Time:        utiltime.NewTime(now),
	}
}
