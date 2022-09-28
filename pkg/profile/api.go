/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package profile

import (
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
)

type ID = string

type Method string

const (
	WebDIDMethod Method = "web"
	KeyDIDMethod Method = key.DIDMethod
	OrbDIDMethod Method = orb.DIDMethod
)

// Issuer profile.
type Issuer struct {
	ID             ID             `json:"id"`
	Name           string         `json:"name,omitempty"`
	URL            string         `json:"url,omitempty"`
	Active         bool           `json:"active"`
	OIDCConfig     interface{}    `json:"oidcConfig"`
	OrganizationID string         `json:"organizationID,omitempty"`
	VCConfig       *VCConfig      `json:"vcConfig"`
	KMSConfig      *vcskms.Config `json:"kmsConfig"`
	SigningDID     *SigningDID    `json:"signingDID"`
}

// VCConfig describes how to sign verifiable credentials.
type VCConfig struct {
	Format                  vcsverifiable.Format               `json:"format,omitempty"`
	SigningAlgorithm        vcsverifiable.SignatureType        `json:"signingAlgorithm,omitempty"`
	KeyType                 kms.KeyType                        `json:"keyType,omitempty"`
	DIDMethod               Method                             `json:"didMethod,omitempty"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation,omitempty"`
	Status                  interface{}                        `json:"status,omitempty"`
	Context                 []string                           `json:"context,omitempty"`
}

// Verifier profile.
type Verifier struct {
	ID             ID                  `json:"id,omitempty"`
	Name           string              `json:"name,omitempty"`
	URL            string              `json:"url,omitempty"`
	Active         bool                `json:"active,omitempty"`
	OrganizationID string              `json:"organizationID,omitempty"`
	Checks         *VerificationChecks `json:"checks,omitempty"`
	OIDCConfig     *OIDC4VPConfig      `json:"oidcConfig,omitempty"`
	KMSConfig      *vcskms.Config      `json:"kmsConfig,omitempty"`
	SigningDID     *SigningDID         `json:"signingDID,omitempty"`
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
	Proof  bool                   `json:"proof,omitempty"`
	Format []vcsverifiable.Format `json:"format,omitempty"`
}

// CredentialChecks are checks to be performed during credential verification.
type CredentialChecks struct {
	Proof  bool                   `json:"proof,omitempty"`
	Format []vcsverifiable.Format `json:"format,omitempty"`
	Status bool                   `json:"status,omitempty"`
}

// SigningDID contains information about profile signing did.
type SigningDID struct {
	DID            string `json:"did,omitempty"`
	Creator        string `json:"creator,omitempty"`
	UpdateKeyURL   string `json:"updateKeyURL,omitempty"`
	RecoveryKeyURL string `json:"recoveryKeyURL,omitempty"`
}
