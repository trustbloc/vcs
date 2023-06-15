/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

type (
	ID      = string // ID of the Profile.
	Version = string // Profile version.
	Method  string   // DID method of the Profile.
)

const (
	WebDIDMethod Method = "web"
	KeyDIDMethod Method = key.DIDMethod
	OrbDIDMethod Method = orb.DIDMethod
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
}

type CredentialTemplate struct {
	Contexts                            []string                 `json:"contexts"`
	ID                                  string                   `json:"id"`
	Type                                string                   `json:"type"`
	CredentialSubject                   json.RawMessage          `json:"credentialSubject"`
	CredentialDefaultExpirationDuration *time.Duration           `json:"credentialDefaultExpirationDuration"`
	Checks                              CredentialTemplateChecks `json:"checks"`
}

type CredentialTemplateChecks struct {
	Strict bool `json:"strict,omitempty"`
}

type CredentialMetaData struct {
	CredentialsSupported []map[string]interface{} `json:"credentials_supported"`
}

// OIDCConfig represents issuer's OIDC configuration.
type OIDCConfig struct {
	IssuerWellKnownURL                string        `json:"issuer_well_known"`
	ClientID                          string        `json:"client_id"`
	ClientSecretHandle                string        `json:"client_secret_handle"`
	ScopesSupported                   []string      `json:"scopes_supported"`
	GrantTypesSupported               []string      `json:"grant_types_supported"`
	ResponseTypesSupported            []string      `json:"response_types_supported"`
	TokenEndpointAuthMethodsSupported []string      `json:"token_endpoint_auth_methods_supported"`
	EnableDynamicClientRegistration   bool          `json:"enable_dynamic_client_registration"`
	InitialAccessTokenLifespan        time.Duration `json:"initial_access_token_lifespan"`
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
	Credential   CredentialChecks    `json:"credential,omitempty"`
	Presentation *PresentationChecks `json:"presentation,omitempty"`
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
}

// SigningDID contains information about profile signing did.
type SigningDID struct {
	DID            string `json:"did,omitempty"`
	Creator        string `json:"creator,omitempty"`
	KMSKeyID       string `json:"kmsKeyID,omitempty"`
	UpdateKeyURL   string `json:"updateKeyURL,omitempty"`
	RecoveryKeyURL string `json:"recoveryKeyURL,omitempty"`
}
