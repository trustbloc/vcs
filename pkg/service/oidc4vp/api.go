/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"context"
	"errors"

	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var ErrDataNotFound = errors.New("data not found")

type InteractionInfo struct {
	AuthorizationRequest string
	TxID                 TxID
}

type Claims = map[string]interface{}

type AuthorizationResponseParsed struct {
	// CustomScopeClaims stores additional claims provided by Holder
	// caused by custom scope as a part of Initiate Credential Presentation request.
	CustomScopeClaims map[string]Claims
	VPTokens          []*ProcessedVPToken
	AttestationVP     string
	Attachments       map[string]string // Attachments from IDToken for AttachmentEvidence type
}

type ProcessedVPToken struct {
	Nonce         string
	ClientID      string
	SignerDIDID   string
	VpTokenFormat vcsverifiable.Format
	Presentation  *verifiable.Presentation
}

type CredentialMetadata struct {
	Format         vcsverifiable.Format `json:"format,omitempty"`
	Type           []string             `json:"type,omitempty"`
	SubjectData    interface{}          `json:"subjectData,omitempty"`
	Issuer         interface{}          `json:"issuer,omitempty"`
	IssuanceDate   *util.TimeWrapper    `json:"issuanceDate,omitempty"`
	ExpirationDate *util.TimeWrapper    `json:"expirationDate,omitempty"`
	ValidFrom      *util.TimeWrapper    `json:"validFrom,omitempty"`
	ValidUntil     *util.TimeWrapper    `json:"validUntil,omitempty"`
	CustomClaims   map[string]Claims    `json:"customClaims,omitempty"`

	Name        interface{}   `json:"name,omitempty"`
	AwardedDate interface{}   `json:"awardedDate,omitempty"`
	Description interface{}   `json:"description,omitempty"`
	Attachments []*Attachment `json:"attachments"`
}

type WalletNotification struct {
	TxID             TxID
	Error            string
	ErrorDescription string
}

type ServiceInterface interface {
	InitiateOidcInteraction(
		ctx context.Context,
		presentationDefinition *presexch.PresentationDefinition,
		purpose string,
		customScopes []string,
		customURLScheme string,
		profile *profileapi.Verifier,
	) (*InteractionInfo, error)
	VerifyOIDCVerifiablePresentation(ctx context.Context, txID TxID, authResponse *AuthorizationResponseParsed) error
	GetTx(ctx context.Context, id TxID) (*Transaction, error)
	RetrieveClaims(ctx context.Context, tx *Transaction, profile *profileapi.Verifier) map[string]CredentialMetadata
	DeleteClaims(ctx context.Context, receivedClaimsID string) error
	HandleWalletNotification(ctx context.Context, req *WalletNotification) error
}

type EventPayload struct {
	WebHook                  string                    `json:"webHook,omitempty"`
	ProfileID                string                    `json:"profileID,omitempty"`
	ProfileVersion           string                    `json:"profileVersion,omitempty"`
	OrgID                    string                    `json:"orgID,omitempty"`
	PresentationDefinitionID string                    `json:"presentationDefinitionID,omitempty"`
	Filter                   *Filter                   `json:"filter,omitempty"`
	AuthorizationRequest     string                    `json:"authorizationRequest,omitempty"`
	Error                    string                    `json:"error,omitempty"`
	ErrorCode                string                    `json:"errorCode,omitempty"`
	ErrorComponent           string                    `json:"errorComponent,omitempty"`
	Credentials              []*CredentialEventPayload `json:"credentials,omitempty"`
}

type Filter struct {
	Fields []string `json:"fields"`
}

type CredentialEventPayload struct {
	ID        string   `json:"id,omitempty"`
	Types     []string `json:"types,omitempty"`
	SubjectID string   `json:"subjectID,omitempty"`
	IssuerID  string   `json:"issuerID,omitempty"`
}

type TxNonceStore txNonceStore

type TxClaimsStore txClaimsStore

type TxStore txStore

// RequestObject represents the request object sent to the wallet. It contains the presentation definition
// that specifies what verifiable credentials should be sent back by the wallet.
type RequestObject struct {
	JTI            string `json:"jti"`
	IAT            int64  `json:"iat"`
	ISS            string `json:"iss"`
	ResponseType   string `json:"response_type"`
	ResponseMode   string `json:"response_mode"`
	ResponseURI    string `json:"response_uri"`
	Scope          string `json:"scope"`
	Nonce          string `json:"nonce"`
	ClientID       string `json:"client_id"`
	ClientIDScheme string `json:"client_id_scheme"`
	RedirectURI    string `json:"redirect_uri"`
	State          string `json:"state"`
	Exp            int64  `json:"exp"`
	// Deprecated: Use client_metadata instead.
	Registration RequestObjectRegistration `json:"registration"`
	// Deprecated: Use top-level "presentation_definition" instead.
	Claims                 RequestObjectClaims              `json:"claims"`
	ClientMetadata         *ClientMetadata                  `json:"client_metadata"`
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

type RequestObjectRegistration struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
	LogoURI                     string           `json:"logo_uri"`
}

type RequestObjectClaims struct {
	VPToken VPToken `json:"vp_token"`
}

type VPToken struct {
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

type ClientMetadata struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
	LogoURI                     string           `json:"logo_uri"`
}

type attachmentData struct {
	Type  string
	Claim map[string]interface{}
}

type Attachment struct {
	ID          string `json:"id"`
	DataURI     string `json:"data_uri"`
	Description string `json:"description"`
	Error       string `json:"error,omitempty"`
}
