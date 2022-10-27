/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import "time"

func WithDocumentTTL(ttl time.Duration) func(insertOptions *InsertOptions) {
	return func(insertOptions *InsertOptions) {
		insertOptions.TTL = ttl
	}
}
