/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientmanager

import (
	"context"
	"fmt"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

// ServiceInterface defines an interface for OAuth2 clients manager.
type ServiceInterface interface {
	Create(ctx context.Context, profileID, profileVersion string, data *ClientMetadata) (*oauth2client.Client, error)
}

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
	Code        ErrorCode `json:"error"`
	Description string    `json:"error_description"`
}

// Error returns a string representation of the error.
func (r *RegistrationError) Error() string {
	return fmt.Sprintf("ERROR: %s, DESCRIPTION: %s", r.Code, r.Description)
}
