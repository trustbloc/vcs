/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

// Model for creating issuer profile.
type createIssuerProfileData struct {
	CredentialManifests []map[string]interface{} `json:"credentialManifests,omitempty"`

	// Model for KMS configuration.
	KmsConfig *kmsConfig `json:"kmsConfig,omitempty"`

	// Issuer’s display name.
	Name string `json:"name"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig map[string]interface{} `json:"oidcConfig,omitempty"`

	// Unique identifier of the organization.
	OrganizationID string `json:"organizationID"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url"`

	// Model for VC configuration.
	VcConfig vcConfig `json:"vcConfig"`
}

type issuerProfile struct {
	// Is profile active? Can be modified using disable/enable profile endpoints.
	Active              bool                      `json:"active"`
	CredentialManifests *[]map[string]interface{} `json:"credentialManifests,omitempty"`

	// Short unique string across the VCS platform, to be used as a reference to this profile.
	Id string `json:"id"`

	// Model for KMS configuration.
	KmsConfig *kmsConfig `json:"kmsConfig,omitempty"`

	// Issuer’s display name.
	Name string `json:"name"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig *map[string]interface{} `json:"oidcConfig,omitempty"`

	// Unique identifier of the organization.
	OrganizationID string `json:"organizationID"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url"`

	// Model for VC configuration.
	VcConfig vcConfig `json:"vcConfig"`
}

// Model for KMS configuration.
type kmsConfig struct {
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

// Model for updating issuer profile data.
type updateIssuerProfileData struct {
	// Issuer’s display name.
	Name string `json:"name,omitempty"`

	// Configuration for OIDC4VC credential interaction operations.
	OidcConfig map[string]interface{} `json:"oidcConfig,omitempty"`

	// URI of the issuer, Refer issuer from VC data model.
	Url string `json:"url,omitempty"`
}

// Model for VC configuration.
type vcConfig struct {
	// Additional JSON-LD contexts the profile is going to use on top of standard W3C verifiable credential contexts and VCS contexts (status, signature suite, etc).
	Contexts []string `json:"contexts,omitempty"`

	// DID method of the DID to be used for signing.
	DidMethod vcConfigDidMethod `json:"didMethod"`

	// Supported VC formats.
	Format vcConfigFormat `json:"format"`

	// Type of key used for signing algorithms. Required only for signing algorithms that do not implicitly specify key type.
	KeyType string `json:"keyType,omitempty"`

	// List of supported cryptographic signing algorithms.
	SigningAlgorithm string `json:"signingAlgorithm"`

	// DID to be used for signing.
	SigningDID string `json:"signingDID"`

	// Credential status type allowed for the profile.
	Status map[string]interface{} `json:"status,omitempty"`
}

// DID method of the DID to be used for signing.
type vcConfigDidMethod string

// Supported VC formats.
type vcConfigFormat string
