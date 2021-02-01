/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// Profile is a client's profile.
type Profile struct {
	ID   string `json:"id"`
	ZCAP string `json:"zcap"`
}

// Query is an abstract query object.
type Query struct {
	ID string `json:"id"`
	// discriminator: true
	Type string `json:"type"`
}

// DocQuery is a concrete Query object that identifies a specific document.
type DocQuery struct {
	// swagger:allOf Query
	Query
	UpstreamAuth struct {
		EDV UpstreamAuthorization `json:"edv"`
		KMS UpstreamAuthorization `json:"kms"`
	} `json:"upstreamAuth"`
}

// RefQuery is a concrete Query object that references another Query object.
type RefQuery struct {
	Query
	Ref string `json:"ref"`
}

// UpstreamAuthorization is an authorization needed for the upstream system.
type UpstreamAuthorization struct {
	BaseURL string `json:"baseURL"`
	ZCAP    string `json:"zcap"`
}

// Authorization is given to requesting parties to allow them access to protected resources.
type Authorization struct {
	ID              string `json:"id"`
	RequestingParty string `json:"requestingParty"`
	Scope           Scope  `json:"scope"`
}

// Scope is the scope of the authorized access.
type Scope struct {
	ResourceID   string   `json:"resourceID"`
	ResourceType string   `json:"resourceType"`
	Action       []string `json:"action"`
	Caveat       Caveat   `json:"caveat"`
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
