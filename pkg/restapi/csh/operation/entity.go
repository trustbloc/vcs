/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
)

// Query is a resource under a profile that specifies a query spec.
type Query struct {
	ID        string
	ProfileID string
	Spec      json.RawMessage
}
