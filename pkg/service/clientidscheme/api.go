/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientidscheme

import "context"

// ServiceInterface defines an interface for OAuth 2.0 Client ID Scheme service.
type ServiceInterface interface {
	Register(ctx context.Context, clientURI, issuerState string) error
}
