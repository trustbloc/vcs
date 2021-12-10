/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapldutil

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// CapabilityInvocationAction returns a KMS invocation action for the given request.
func CapabilityInvocationAction(req *http.Request) (string, error) { //nolint:funlen,gocognit,gocyclo
	s := strings.Split(req.URL.Path, "/")

	const minPathLen = 5 // /v1/keystores/{key_store_id}/keys

	if len(s) < minPathLen {
		return "", errors.New("invalid path")
	}

	op := strings.ToLower(s[4])

	var action string

	switch op {
	case "keys":
		op = strings.ToLower(s[len(s)-1])

		switch op {
		case "sign":
			if req.Method == http.MethodPost {
				action = "sign"
			}
		case "verify":
			if req.Method == http.MethodPost {
				action = "verify"
			}
		case "encrypt":
			if req.Method == http.MethodPost {
				action = "encrypt"
			}
		case "decrypt":
			if req.Method == http.MethodPost {
				action = "decrypt"
			}
		case "computemac":
			if req.Method == http.MethodPost {
				action = "computeMAC"
			}
		case "verifymac":
			if req.Method == http.MethodPost {
				action = "verifyMAC"
			}
		case "signmulti":
			if req.Method == http.MethodPost {
				action = "signMulti"
			}
		case "verifymulti":
			if req.Method == http.MethodPost {
				action = "verifyMulti"
			}
		case "deriveproof":
			if req.Method == http.MethodPost {
				action = "deriveProof"
			}
		case "verifyproof":
			if req.Method == http.MethodPost {
				action = "verifyProof"
			}
		case "easy":
			if req.Method == http.MethodPost {
				action = "easy"
			}
		case "wrap": //nolint:goconst
			if req.Method == http.MethodPost {
				action = "wrap"
			}
		case "unwrap":
			if req.Method == http.MethodPost {
				action = "unwrap"
			}
		default:
			if req.Method == http.MethodPost {
				action = "createKey"
			}

			if req.Method == http.MethodPut {
				action = "importKey"
			}

			if req.Method == http.MethodGet && op != "keys" {
				action = "exportKey"
			}
		}
	case "wrap":
		if req.Method == http.MethodPost {
			action = "wrap"
		}
	case "easyopen":
		if req.Method == http.MethodPost {
			action = "easyOpen"
		}
	case "sealopen":
		if req.Method == http.MethodPost {
			action = "sealOpen"
		}
	}

	if action == "" {
		return "", fmt.Errorf("unsupported operation: %s /%s", req.Method, op)
	}

	return action, nil
}
