/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"strings"
)

const (
	WalletInitFlowClaimExpectedMatchCount = 2
)

func ExtractIssuerURLFromScopes(scopes []string) string {
	for _, scope := range scopes {
		if strings.HasPrefix(scope, "http://") || strings.HasPrefix(scope, "https://") {
			return scope
		}
	}

	return ""
}
