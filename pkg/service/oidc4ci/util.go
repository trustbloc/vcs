/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"fmt"
	"strings"
	"time"
)

func WithDocumentTTL(ttl time.Duration) func(insertOptions *InsertOptions) {
	return func(insertOptions *InsertOptions) {
		insertOptions.TTL = ttl
	}
}

func MapCredentialFormat(old string) (string, error) {
	switch strings.ToLower(old) {
	case "jwt":
		return "jwt_vc_json", nil
	case "ldp":
		return "ldp_vc", nil
	default:
		return "", fmt.Errorf("unsupported vc mapping for format: %v", old)
	}
}
