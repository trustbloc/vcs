/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/ory/fosite"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

// ServiceInterface defines an interface for OAuth2 client manager.
type ServiceInterface interface {
	Create(ctx context.Context, profileID, profileVersion string, data *ClientMetadata) (*oauth2client.Client, error)
	Get(ctx context.Context, id string) (fosite.Client, error)
}

var (
	ErrClientNotFound = errors.New("client not found")
)

// ErrorCode is an error code for client registration error response as defined in
// https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2.
type ErrorCode string

const (
	// ErrCodeInvalidRedirectURI defines error case when the value of one or more redirection URIs is invalid.
	ErrCodeInvalidRedirectURI ErrorCode = "invalid_redirect_uri"
	// ErrCodeInvalidClientMetadata defines error case when the value of one of the client metadata fields is invalid
	// and the server has rejected this request.
	ErrCodeInvalidClientMetadata ErrorCode = "invalid_client_metadata"
	// ErrCodeInvalidSoftwareStatement defines error case when the software statement presented is invalid.
	ErrCodeInvalidSoftwareStatement ErrorCode = "invalid_software_statement"
	// ErrCodeUnapprovedSoftwareStatement defines error case when the software statement presented is not approved for
	// use by the server.
	ErrCodeUnapprovedSoftwareStatement ErrorCode = "unapproved_software_statement"
)

// RegistrationError defines a registration error in client registration response. When a registration error occurs,
// the server returns an HTTP 400 status code.
type RegistrationError struct {
	Code         ErrorCode `json:"error"`
	InvalidValue string    `json:"invalid_value,omitempty"`
	Err          error     `json:"-"` // wrapped error
}

// InvalidClientMetadataError creates a new RegistrationError with ErrCodeInvalidClientMetadata error code.
func InvalidClientMetadataError(invalidValue string, err error) *RegistrationError {
	return &RegistrationError{
		Code:         ErrCodeInvalidClientMetadata,
		InvalidValue: invalidValue,
		Err:          err,
	}
}

// Error returns a string representation of the error.
func (r *RegistrationError) Error() string {
	switch {
	case r.Err != nil:
		return r.Err.Error()
	case r.InvalidValue != "":
		return fmt.Sprintf("%s (%s)", string(r.Code), r.InvalidValue)
	default:
		return string(r.Code)
	}
}
