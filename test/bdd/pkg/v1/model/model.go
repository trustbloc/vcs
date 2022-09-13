/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// CreateIssuerProfileData model for creating issuer profile.
type CreateIssuerProfileData struct {
	CredentialManifests []map[string]interface{} `json:"credentialManifests,omitempty"`

	// Model for KMS configuration.
	KmsConfig *KMSConfig `json:"kmsConfig,omitempty"`

	// Issuer’s display name.
	Name string `json:"name"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig map[string]interface{} `json:"oidcConfig,omitempty"`

	// Unique identifier of the organization.
	OrganizationID string `json:"organizationID"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url"`

	// Model for VC configuration.
	VcConfig VCConfig `json:"vcConfig"`
}
// IssuerProfile model for issuer profile.
type IssuerProfile struct {
	// Is profile active? Can be modified using disable/enable profile endpoints.
	Active              bool                      `json:"active"`
	CredentialManifests *[]map[string]interface{} `json:"credentialManifests,omitempty"`

	// Short unique string across the VCS platform, to be used as a reference to this profile.
	Id string `json:"id"`

	// Model for KMS configuration.
	KmsConfig *KMSConfig `json:"kmsConfig,omitempty"`

	// Issuer’s display name.
	Name string `json:"name"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig *map[string]interface{} `json:"oidcConfig,omitempty"`

	// Unique identifier of the organization.
	OrganizationID string `json:"organizationID"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url"`

	// Model for VC configuration.
	VcConfig VCConfig `json:"vcConfig"`
}

// KMSConfig model for KMS configuration.
type KMSConfig struct {
	// Prefix of database used by local kms.
	DbPrefix string `json:"dbPrefix,omitempty"`

	// Type of database used by local kms.
	DbType string `json:"dbType,omitempty"`

	// URL to database used by local kms.
	DbURL string `json:"dbURL,omitempty"`

	// KMS endpoint.
	Endpoint string `json:"endpoint,omitempty"`

	// Path to secret lock used by local kms.
	SecretLockKeyPath string `json:"secretLockKeyPath,omitempty"`

	// Type of kms used to create and store DID keys.
	Type kmsConfigType `json:"type"`
}

// Type of kms used to create and store DID keys.
type kmsConfigType string

// UpdateIssuerProfileData model for updating issuer profile data.
type UpdateIssuerProfileData struct {
	// Issuer’s display name.
	Name string `json:"name,omitempty"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig map[string]interface{} `json:"oidcConfig,omitempty"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url,omitempty"`
}

// VCConfig model for VC configuration.
type VCConfig struct {
	// Additional JSON-LD contexts the profile is going to use on top of standard W3C verifiable credential contexts and VCS contexts (status, signature suite, etc).
	Contexts []string `json:"contexts,omitempty"`

	// DID method of the DID to be used for signing.
	DidMethod string `json:"didMethod"`

	// Supported VC formats.
	Format string `json:"format"`

	// Type of key used for signing algorithms. Required only for signing algorithms that do not implicitly specify key type.
	KeyType string `json:"keyType,omitempty"`

	// Type of signature value holder (e.g. "ProofValue" or "JWS").
	SignatureRepresentation string `json:"signatureRepresentation,omitempty"`

	// List of supported cryptographic signing algorithms.
	SigningAlgorithm string `json:"signingAlgorithm"`

	// DID to be used for signing.
	SigningDID string `json:"signingDID"`

	// Credential status type allowed for the profile.
	Status map[string]interface{} `json:"status,omitempty"`
}

// Model for issuer credential.
type IssueCredentialData struct {
	// URI of the verifier.
	Credential interface{} `json:"credential"`

	// Options for issuing credential.
	Options *IssueCredentialOptions `json:"options,omitempty"`
}

// Options for issuing credential.
type IssueCredentialOptions struct {
	// Chalange is added to the proof.
	Challenge *string `json:"challenge,omitempty"`

	// The date of the proof. If omitted system time will be used.
	Created *string `json:"created,omitempty"`

	// Options for issuing credential.
	CredentialStatus *CredentialStatusOpt `json:"credentialStatus,omitempty"`

	// Domain is added to the proof.
	Domain *string `json:"domain,omitempty"`

	// The URI of the verificationMethod used for the proof. If omitted first ed25519 public key of DID (Issuer or Profile DID) will be used.
	VerificationMethod *string `json:"verificationMethod,omitempty"`
}

// Options for issuing credential.
type CredentialStatusOpt struct {
	Type string `json:"type"`
}
