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
	DataConfig          IssuerDataConfig      `json:"dataConfig"`
}

// IssuerDataConfig stores profile specific transient data configuration.
type IssuerDataConfig struct {
	ClaimDataTTL              int32
	OIDC4CITransactionDataTTL int32
	OIDC4CIAuthStateTTL       int32
	OIDC4CIAckDataTTL         int32
}

type CredentialMetaData struct {
	CredentialsConfigurationSupported map[string]*CredentialsConfigurationSupported `json:"credential_configurations_supported"` //nolint:lll
	Display                           []*CredentialDisplay                          `json:"display"`
}

// CredentialsConfigurationSupported describes specifics of the Credential that the Issuer supports issuance of.
type CredentialsConfigurationSupported struct {
	// For mso_mdoc and vc+sd-jwt vc only. Object containing a list of name/value pairs,
	// where each name identifies a claim about the subject offered in the Credential.
	// The value can be another such object (nested data structures), or an array of such objects.
	Claims map[string]interface{} `json:"claims"`

	// Object containing the detailed description of the credential type.
	CredentialDefinition *CredentialDefinition `json:"credential_definition"`

	// An array of objects, where each object contains the display properties
	// of the supported credential for a certain language.
	Display []*CredentialDisplay `json:"display"`

	// For mso_mdoc vc only. String identifying the Credential type, as defined in [ISO.18013-5].
	Doctype string `json:"doctype"`

	// A JSON string identifying the format of this credential, i.e., jwt_vc_json or ldp_vc.
	Format vcsverifiable.OIDCFormat `json:"format"`

	// Array of the claim name values that lists them in the order they should be displayed by the Wallet.
	Order []string `json:"order"`

	// A JSON string identifying the scope value that this Credential Issuer supports for this particular credential.
	Scope string `json:"scope"`

	// For vc+sd-jwt vc only. String designating the type of a Credential,
	// as defined in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-01
	Vct string `json:"vct"`
}

// CredentialDefinition containing the detailed description of the credential type.
type CredentialDefinition struct {
	// For ldp_vc only. Array as defined in https://www.w3.org/TR/vc-data-model/#contexts.
	Context []string `json:"@context"`

	// An object containing a list of name/value pairs, where each name identifies a claim offered in the Credential.
	// The value can be another such object (nested data structures), or an array of such objects.
	CredentialSubject map[string]Claim `json:"credentialSubject"`

	// Array designating the types a certain credential type supports
	Type []string `json:"type"`
}

type Claim struct {
	Mandatory bool   `json:"mandatory"`
	ValueType string `json:"value_type"`
	Pattern   string `json:"pattern"`
	Mask      string `json:"mask"`
	Display   []L10n `json:"display"`
}

type L10n struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

type CredentialDisplay struct {
	Name            string `json:"name"`
	Locale          string `json:"locale"`
	URL             string `json:"url"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
	Logo            *Logo  `json:"logo"`
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
	URI             string `json:"uri"`
	AlternativeText string `json:"alt_text"`
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
	CredentialResponseAlgValuesSupported       []string `json:"credential_response_alg_values_supported"`
	CredentialResponseEncValuesSupported       []string `json:"credential_response_enc_values_supported"`
	CredentialResponseEncryptionRequired       bool     `json:"credential_response_encryption_required"`
	ClaimsEndpoint                             string   `json:"claims_endpoint"`
}

// VCConfig describes how to sign verifiable credentials.
type VCConfig struct {
	Model                   vcsverifiable.Model                `json:"model,omitempty"`
	Format                  vcsverifiable.Format               `json:"format,omitempty"`
	SigningAlgorithm        vcsverifiable.SignatureType        `json:"signingAlgorithm,omitempty"`
	KeyType                 kms.KeyType                        `json:"keyType,omitempty"`
	DIDMethod               Method                             `json:"didMethod,omitempty"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation,omitempty"`
	Status                  StatusConfig                       `json:"status,omitempty"`
	Context                 []string                           `json:"context,omitempty"`
	SDJWT                   vc.SDJWT                           `json:"sdjwt,omitempty"`
	DataIntegrityProof      vc.DataIntegrityProofConfig        `json:"dataIntegrityProof,omitempty"`
	RefreshServiceEnabled   bool                               `json:"refreshServiceEnabled,omitempty"`
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
	DataConfig              VerifierDataConfig                 `json:"dataConfig"`
}

// VerifierDataConfig stores profile specific transient data configuration.
type VerifierDataConfig struct {
	OIDC4VPNonceStoreDataTTL     int32
	OIDC4VPTransactionDataTTL    int32
	OIDC4VPReceivedClaimsDataTTL int32
}

// OIDC4VPConfig store config for verifier did that used to sign request object in oidc4vp process.
type OIDC4VPConfig struct {
	ROSigningAlgorithm vcsverifiable.SignatureType `json:"roSigningAlgorithm,omitempty"`
	DIDMethod          Method                      `json:"didMethod,omitempty"`
	KeyType            kms.KeyType                 `json:"keyType,omitempty"`
}

// VerificationChecks are checks to be performed for verifying credentials and presentations.
type VerificationChecks struct {
	Credential   CredentialChecks    `json:"credential,omitempty"`
	Presentation *PresentationChecks `json:"presentation,omitempty"`
	Policy       PolicyCheck         `json:"policy,omitempty"`
}

// IssuanceChecks are checks to be performed for issuance credentials and presentations.
type IssuanceChecks struct {
	Policy PolicyCheck `json:"policy,omitempty"`
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
