/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vci

import (
	"time"

	"github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type ProofClaims struct {
	Issuer   string `json:"iss,omitempty" cbor:"1,keyasint"`
	Audience string `json:"aud,omitempty" cbor:"3,keyasint"`
	IssuedAt *int64 `json:"iat,omitempty" cbor:"6,keyasint"`
	Nonce    string `json:"nonce,omitempty" cbor:"10,keyasint"`
}

type CredentialRequest struct {
	Format                       verifiable.OIDCFormat         `json:"format,omitempty"`
	CredentialDefinition         *CredentialDefinition         `json:"credential_definition,omitempty"`
	CredentialIdentifier         *string                       `json:"credential_identifier,omitempty"`
	Proof                        Proof                         `json:"proof,omitempty"`
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption,omitempty"`
}

// CredentialDefinition contains the detailed description of the credential type.
type CredentialDefinition struct {
	// For ldp_vc only. Array as defined in https://www.w3.org/TR/vc-data-model/#contexts.
	Context *[]string `json:"@context,omitempty"`
	// An object containing a list of name/value pairs, where each name identifies a claim offered in the Credential. The value can be another such object (nested data structures), or an array of such objects.
	CredentialSubject *map[string]interface{} `json:"credentialSubject,omitempty"`
	// Array designating the types a certain credential type supports
	Type []string `json:"type"`
}

// CredentialResponseEncryption containing information for encrypting the Credential Response.
type CredentialResponseEncryption struct {
	// JWE alg algorithm for encrypting the Credential Response.
	Alg string `json:"alg"`

	// JWE enc algorithm for encrypting the Credential Response.
	Enc string `json:"enc"`

	// Object containing a single public key as a JWK used for encrypting the Credential Response.
	Jwk string `json:"jwk"`
}

type BatchCredentialRequest struct {
	CredentialRequests []CredentialRequest `json:"credential_requests"`
}

// BatchCredentialResponse for OIDC Batch Credential response.
type BatchCredentialResponse struct {
	// JSON string containing a nonce to be used to create a proof of possession of key material when requesting a Credential.
	CNonce *string `json:"c_nonce,omitempty"`

	// JSON integer denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn     *int                                `json:"c_nonce_expires_in,omitempty"`
	CredentialResponses []CredentialResponseBatchCredential `json:"credential_responses"`
}

type CredentialResponseBatchCredential struct {
	// Contains issued Credential.
	Credential interface{} `json:"credential"`

	// String identifying an issued Credential that the Wallet includes in the acknowledgement request.
	NotificationId *string `json:"notification_id,omitempty"`

	// OPTIONAL. String identifying a Deferred Issuance transaction. This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential. The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint.
	TransactionId *string `json:"transaction_id,omitempty"`
}

type Proof struct {
	JWT       string `json:"jwt"`
	CWT       string `json:"cwt"`
	ProofType string `json:"proof_type"`
	LdpVp     any    `json:"ldp_vp,omitempty"`
}

type CredentialResponse struct {
	AcceptanceToken string                `json:"acceptance_token,omitempty"`
	CNonce          string                `json:"c_nonce,omitempty"`
	CNonceExpiresIn int                   `json:"c_nonce_expires_in,omitempty"`
	Credential      interface{}           `json:"credential"`
	Format          verifiable.OIDCFormat `json:"format"`
	NotificationId  *string               `json:"notification_id"`
}

type PerfInfo struct {
	GetIssuerCredentialsOIDCConfig time.Duration `json:"vci_get_issuer_credentials_oidc_config"`
	GetAccessToken                 time.Duration `json:"vci_get_access_token"`
	GetCredential                  time.Duration `json:"vci_get_credential"`
	CredentialsAck                 time.Duration `json:"vci_credentials_ack"`
}

type parseCredentialResponseData struct {
	credential     interface{}
	notificationID *string
}
