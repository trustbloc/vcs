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

func ExtractIssuerURL(input string) string {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return input
	}

	return ""
}
