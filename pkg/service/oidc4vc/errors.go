/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import "errors"

var (
	ErrDataNotFound                    = errors.New("data not found")
	ErrProfileNotActive                = errors.New("profile not active")
	ErrCredentialTemplateNotFound      = errors.New("credential template not found")
	ErrCredentialTemplateNotConfigured = errors.New("credential template not configured")
	ErrCredentialTemplateIDRequired    = errors.New("credential template ID is required")
	ErrAuthorizedCodeFlowNotSupported  = errors.New("authorized code flow not supported")
)
