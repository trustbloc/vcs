/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import "errors"

var (
	ErrDataNotFound                 = errors.New("data not found")
	ErrCredentialTemplateNotFound   = errors.New("credential template not found")
	ErrCredentialTemplateIDRequired = errors.New("credential template ID is required")
)
