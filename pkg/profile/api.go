/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"encoding/json"
	"time"

	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/sdjwt/common"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

type (
	ID      = string // ID of the Profile.
	Version = string // Profile version.

	Method string // DID method of the Profile.
)

const (
	WebDIDMethod Method = "web"
	KeyDIDMethod Method = key.DIDMethod
	OrbDIDMethod Method = "orb"
)

// Issuer profile.
type Issuer struct {
	ID                  ID                    `json:"id"`
	Version             Version               `json:"version"`
	GroupID             ID                    `json:"groupID"`
	Name                string                `json:"name,omitempty"`
	URL                 string                `json:"url,omitempty"`
	Active              bool                  `json:"active"`
	OIDCConfig          *OIDCConfig           `json:"oidcConfig"`
	OrganizationID      string                `json:"organizationID,omitempty"`
	VCConfig            *VCConfig             `json:"vcConfig"`
	KMSConfig           *vcskms.Config        `json:"kmsConfig"`
	SigningDID          *SigningDID           `json:"signingDID"`
	CredentialTemplates []*CredentialTemplate `json:"credentialTemplates,omitempty"`
	WebHook             string                `json:"webHook,omitempty"`
	CredentialMetaData  *CredentialMetaData   `json:"credentialMetadata"`
	Checks              IssuanceChecks        `json:"checks"`
}

type CredentialTemplate struct {
	Contexts                            []string                     `json:"contexts"`
	ID                                  string                       `json:"id"`
	Type                                string                       `json:"type"`
	CredentialSubject                   json.RawMessage              `json:"credentialSubject"`
	CredentialDefaultExpirationDuration *time.Duration               `json:"credentialDefaultExpirationDuration"`
	Checks                              CredentialTemplateChecks     `json:"checks"`
	SdJWT                               *SelectiveDisclosureTemplate `json:"sdJWT"`
	JSONSchema                          string                       `json:"jsonSchema,omitempty"`
	JSONSchemaID                        string                       `json:"jsonSchemaID,omitempty"`
}

type SelectiveDisclosureTemplate struct {
	Version                   common.SDJWTVersion `json:"version"`
	AlwaysInclude             []string            `json:"alwaysInclude"`
	RecursiveClaims           []string            `json:"recursiveClaims"`
	NonSelectivelyDisclosable []string            `json:"nonSelectivelyDisclosable"`
}

type CredentialTemplateChecks struct {
	Strict bool `json:"strict,omitempty"`
}

type Logo struct {
	URL             string `json:"url"`
	AlternativeText string `json:"alt_text"`
}

type CredentialDisplay struct {
	Name            string `json:"name"`
	Locale          string `json:"locale"`
	URL             string `json:"url"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	Logo            *Logo  `json:"logo"`
}

type CredentialMetaData struct {
	CredentialsSupported []map[string]interface{} `json:"credentials_supported"`
	Display              []*CredentialDisplay     `json:"display"`
}

// OIDCConfig represents issuer's OIDC configuration.
type OIDCConfig struct {
	IssuerWellKnownURL                         string   `json:"issuer_well_known"`
	ClientID                                   string   `json:"client_id"`
	ClientSecretHandle                         string   `json:"client_secret_handle"`
	ScopesSupported                            []string `json:"scopes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	EnableDynamicClientRegistration            bool     `json:"enable_dynamic_client_registration"`
	EnableDiscoverableClientIDScheme           bool     `json:"enable_discoverable_client_id_scheme"`
	PreAuthorizedGrantAnonymousAccessSupported bool     `json:"pre-authorized_grant_anonymous_access_supported"`
	WalletInitiatedAuthFlowSupported           bool     `json:"wallet_initiated_auth_flow_supported"`
	SignedCredentialOfferSupported             bool     `json:"signed_credential_offer_supported"`
	SignedIssuerMetadataSupported              bool     `json:"signed_issuer_metadata_supported"`
	ClaimsEndpoint                             string   `json:"claims_endpoint"`
}

// VCConfig describes how to sign verifiable credentials.
type VCConfig struct {
	Format                  vcsverifiable.Format               `json:"format,omitempty"`
	SigningAlgorithm        vcsverifiable.SignatureType        `json:"signingAlgorithm,omitempty"`
	KeyType                 kms.KeyType                        `json:"keyType,omitempty"`
	DIDMethod               Method                             `json:"didMethod,omitempty"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation,omitempty"`
	Status                  StatusConfig                       `json:"status,omitempty"`
	Context                 []string                           `json:"context,omitempty"`
	SDJWT                   vc.SDJWT                           `json:"sdjwt,omitempty"`
	DataIntegrityProof      vc.DataIntegrityProofConfig        `json:"dataIntegrityProof,omitempty"`
}

// StatusConfig represents the VC status configuration.
type StatusConfig struct {
	Type    vc.StatusType `json:"type"`
	Disable bool          `json:"disable"`
}

// Verifier profile.
type Verifier struct {
	ID                      ID                                 `json:"id,omitempty"`
	Version                 Version                            `json:"version,omitempty"`
	Name                    string                             `json:"name,omitempty"`
	URL                     string                             `json:"url,omitempty"`
	LogoURL                 string                             `json:"logoURL,omitempty"`
	Active                  bool                               `json:"active,omitempty"`
	OrganizationID          string                             `json:"organizationID,omitempty"`
	Checks                  *VerificationChecks                `json:"checks,omitempty"`
	OIDCConfig              *OIDC4VPConfig                     `json:"oidcConfig,omitempty"`
	KMSConfig               *vcskms.Config                     `json:"kmsConfig,omitempty"`
	SigningDID              *SigningDID                        `json:"signingDID,omitempty"`
	PresentationDefinitions []*presexch.PresentationDefinition `json:"presentationDefinitions,omitempty"`
	WebHook                 string                             `json:"webHook,omitempty"`
}

// OIDC4VPConfig store config for verifier did that used to sign request object in oidc4vp process.
type OIDC4VPConfig struct {
	ROSigningAlgorithm vcsverifiable.SignatureType `json:"roSigningAlgorithm,omitempty"`
	DIDMethod          Method                      `json:"didMethod,omitempty"`
	KeyType            kms.KeyType                 `json:"keyType,omitempty"`
}

// VerificationChecks are checks to be performed for verifying credentials and presentations.
type VerificationChecks struct {
	Credential             CredentialChecks       `json:"credential,omitempty"`
	Presentation           *PresentationChecks    `json:"presentation,omitempty"`
	Policy                 PolicyCheck            `json:"policy,omitempty"`
	ClientAttestationCheck ClientAttestationCheck `json:"clientAttestationCheck,omitempty"`
}

// IssuanceChecks are checks to be performed for issuance credentials and presentations.
type IssuanceChecks struct {
	Policy                 PolicyCheck            `json:"policy,omitempty"`
	ClientAttestationCheck ClientAttestationCheck `json:"clientAttestationCheck,omitempty"`
}

// PolicyCheck stores policy check configuration.
type PolicyCheck struct {
	PolicyURL string `json:"policyUrl"`
}

// ClientAttestationCheck stores Client Attestation check configuration.
type ClientAttestationCheck struct {
	Enabled bool `json:"enabled"`
}

// PresentationChecks are checks to be performed during presentation verification.
type PresentationChecks struct {
	Proof     bool                   `json:"proof,omitempty"`
	VCSubject bool                   `json:"vcSubject,omitempty"`
	Format    []vcsverifiable.Format `json:"format,omitempty"`
}

// CredentialChecks are checks to be performed during credential verification.
type CredentialChecks struct {
	Proof            bool                   `json:"proof,omitempty"`
	Format           []vcsverifiable.Format `json:"format,omitempty"`
	Status           bool                   `json:"status,omitempty"`
	CredentialExpiry bool                   `json:"credentialExpiry,omitempty"`
	Strict           bool                   `json:"strict,omitempty"`
	LinkedDomain     bool                   `json:"linkedDomain,omitempty"`
	IssuerTrustList  map[string]TrustList   `json:"issuerTrustList,omitempty"`
}

// TrustList contains list of configuration that verifier is trusted to accept.
type TrustList struct {
	CredentialTypes []string `json:"credentialTypes,omitempty"`
}

// SigningDID contains information about profile signing did.
type SigningDID struct {
	DID            string `json:"did,omitempty"`
	Creator        string `json:"creator,omitempty"`
	KMSKeyID       string `json:"kmsKeyID,omitempty"`
	UpdateKeyURL   string `json:"updateKeyURL,omitempty"`
	RecoveryKeyURL string `json:"recoveryKeyURL,omitempty"`
}
