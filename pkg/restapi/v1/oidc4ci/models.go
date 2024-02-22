/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

// PushedAuthorizationRequest is a model with custom OIDC4CI-related fields for PAR.
type PushedAuthorizationRequest struct {
	AuthorizationDetails string `form:"authorization_details"`
	OpState              string `form:"op_state"`
}

type ProofClaims struct {
	Issuer   string `json:"iss,omitempty" cbor:"1,keyasint"`
	Audience string `json:"aud,omitempty" cbor:"3,keyasint"`
	IssuedAt *int64 `json:"iat,omitempty" cbor:"6,keyasint"`
	Nonce    string `json:"nonce,omitempty" cbor:"10,keyasint"`
}
