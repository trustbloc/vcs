/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

// PushedAuthorizationRequest is a model with custom OIDC4VC-related fields for PAR.
type PushedAuthorizationRequest struct {
	AuthorizationDetails string `form:"authorization_details"`
	OpState              string `form:"op_state"`
}

// AuthorizationDetails parameter is used to convey the details about VC the Wallet wants to obtain.
// Refer to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.1.1 for more details.
type AuthorizationDetails struct {
	// Type determines the authorization details type. MUST be set to "openid_credential".
	Type string
	// CredentialType denotes the type of the requested Credential.
	CredentialType string
	// Format represents a format in which the Credential is requested to be issued.
	Format *string
	// Locations param is an array of strings that allows a client to specify the location of the resource server(s) for
	// the AS to mint audience restricted access tokens.
	Locations *[]string
}
