/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/base64"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

// IsSDJWT returns true if jwt is SD-JWT.
func IsSDJWT(jwt string) bool {
	if !strings.Contains(jwt, common.CombinedFormatSeparator) {
		return false
	}

	minJWTChunksAmount := 2

	parts := strings.Split(jwt, ".")
	if len(parts) < minJWTChunksAmount {
		return false
	}

	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	return strings.Contains(string(b), common.SDKey) && strings.Contains(string(b), common.SDAlgorithmKey)
}

func UnQuote(s []byte) []byte {
	if len(s) <= 1 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}

	return s
}
