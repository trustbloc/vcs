/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

type Profile struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	URL        string      `json:"url"`
	Checks     interface{} `json:"checks"`
	OIDCConfig interface{} `json:"oidcConfig"`
}
