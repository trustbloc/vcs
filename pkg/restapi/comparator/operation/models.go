/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
)

// Query is an abstract query object.
type Query struct {
	// discriminator: true
	Type string `json:"type"`
}

// DocQuery is a concrete Query object that identifies a specific document.
type DocQuery struct {
	DocID   string `json:"docID"`
	VaultID string `json:"vaultID"`
	// swagger:allOf Query
	Query
	UpstreamAuth struct {
		EDV string `json:"edv"`
		KMS string `json:"kms"`
	} `json:"authTokens"`
}

// Authorization is given to requesting parties to allow them access to protected resources.
type Authorization struct {
	ID              string `json:"id"`
	RequestingParty string `json:"requestingParty"`
	Scope           Scope  `json:"scope"`
	AuthToken       string `json:"authToken"`
}

// Scope is the scope of the authorized access.
type Scope struct {
	DocID   string   `json:"docID"`
	Actions []string `json:"actions"`
	Caveats []Caveat `json:"caveats"`
}

// Caveat are orthogonal, reusable constraints placed on authorization scopes.
type Caveat struct {
	Type string `json:"type"`
}

// ExpiryCaveat is a concrete Caveat that sets a duration on an authorization's scope.
type ExpiryCaveat struct {
	Caveat
	Duration int `json:"duration"`
}

// Operator is an abstract operation.
type Operator struct {
	Type string `json:"type"`
}

// EqualityOperator is a concrete Operator.
type EqualityOperator struct {
	Operator
	Args []Query `json:"args"`
}

// Comparison is the result of a comparison.
type Comparison struct {
	Result bool `json:"result"`
}

// ComparatorConfig config for comparator
type ComparatorConfig struct {
	DID  string            `json:"did"`
	Keys []json.RawMessage `json:"keys"`
}
