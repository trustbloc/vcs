/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import (
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
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

	CredentialStatusStatusUpdated = EventType("credentialstatus_status_updated")
)

type Payload []byte

type Event struct {
	// SpecVersion is spec version(required).
	SpecVersion string `json:"specVersion"`

	// ID identifies the event(required).
	ID string `json:"id"`

	// Source is URI for producer(required).
	Source string `json:"source"`

	// Type defines event type(required).
	Type EventType `json:"type"`

	// Time defines time of occurrence(required).
	Time *util.TimeWrapper `json:"time"`

	// DataContentType is data content type(optional).
	DataContentType string `json:"dataContentType,omitempty"`

	// Data defines message(optional).
	Data []byte `json:"data,omitempty"`

	// TransactionID defines transaction ID(optional).
	TransactionID string `json:"txnId,omitempty"`

	// Subject defines subject(optional).
	Subject string `json:"subject,omitempty"`

	// Tracing defines tracing(optional).
	Tracing string `json:"tracing,omitempty"`
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
		Time:        util.NewTime(now),
	}
}
