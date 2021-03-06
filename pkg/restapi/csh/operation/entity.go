/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Query is a resource under a profile that specifies a query spec.
type Query struct {
	ID        string
	ProfileID string
	Spec      json.RawMessage
}

// Identity is the Confidential Storage Hub's identity.
type Identity struct {
	DIDDoc           *did.Doc
	AuthKeyID        string // Key in the did doc's authentication section.
	DelegationKeyID  string // Used to sign zcaps when delegating access.
	DelegationKeyURL string // Points to DelegationKeyID. This is the verification method used when signing zcaps.
	InvocationKeyID  string // TODO - this is the key that should be authorized by third parties to invoke capabilities.
}
