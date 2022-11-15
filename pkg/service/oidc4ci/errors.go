/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import "errors"

var (
	ErrDataNotFound                    = errors.New("data not found")
	ErrProfileNotActive                = errors.New("profile not active")
	ErrCredentialTemplateNotFound      = errors.New("credential template not found")
	ErrCredentialTemplateNotConfigured = errors.New("credential template not configured")
	ErrCredentialTemplateIDRequired    = errors.New("credential template ID is required")
	ErrAuthorizedCodeFlowNotSupported  = errors.New("authorized code flow not supported")
	ErrResponseTypeMismatch            = errors.New("response type mismatch")
	ErrInvalidScope                    = errors.New("invalid scope")
	ErrCredentialTypeNotSupported      = errors.New("credential type not supported")
	ErrCredentialFormatNotSupported    = errors.New("credential format not supported")
	ErrVCOptionsNotConfigured          = errors.New("vc options not configured")
)
