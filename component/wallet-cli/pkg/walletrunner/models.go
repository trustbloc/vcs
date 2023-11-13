/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	verifiable2 "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type RequestObject struct {
	JTI          string                    `json:"jti"`
	IAT          int64                     `json:"iat"`
	ResponseType string                    `json:"response_type"`
	ResponseMode string                    `json:"response_mode"`
	Scope        string                    `json:"scope"`
	Nonce        string                    `json:"nonce"`
	ClientID     string                    `json:"client_id"`
	RedirectURI  string                    `json:"redirect_uri"`
	State        string                    `json:"state"`
	Exp          int64                     `json:"exp"`
	Registration RequestObjectRegistration `json:"registration"`
	Claims       RequestObjectClaims       `json:"claims"`
}

type RequestObjectRegistration struct {
	ClientName                  string           `json:"client_name"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
	ClientPurpose               string           `json:"client_purpose"`
}

type RequestObjectClaims struct {
	VPToken VPToken `json:"vp_token"`
}

type VPToken struct {
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

type IDTokenVPToken struct {
	PresentationSubmission *presexch.PresentationSubmission `json:"presentation_submission"`
}

type Claims = map[string]interface{}

type IDTokenClaims struct {
	// ScopeAdditionalClaims stores additional claims retrieved using custom scope.
	ScopeAdditionalClaims map[string]Claims `json:"_scope,omitempty"` // custom scope -> additional claims
	VPToken               IDTokenVPToken    `json:"_vp_token"`
	Nonce                 string            `json:"nonce"`
	Exp                   int64             `json:"exp"`
	Iss                   string            `json:"iss"`
	Aud                   string            `json:"aud"`
	Sub                   string            `json:"sub"`
	Nbf                   int64             `json:"nbf"`
	Iat                   int64             `json:"iat"`
	Jti                   string            `json:"jti"`
}

type VPTokenClaims struct {
	VP    *verifiable.Presentation `json:"vp"`
	Nonce string                   `json:"nonce"`
	Exp   int64                    `json:"exp"`
	Iss   string                   `json:"iss"`
	Aud   string                   `json:"aud"`
	Nbf   int64                    `json:"nbf"`
	Iat   int64                    `json:"iat"`
	Jti   string                   `json:"jti"`
}

type InitiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxId                 string `json:"txID"`
}

type JWTProofClaims struct {
	Issuer   string `json:"iss,omitempty"`
	Audience string `json:"aud,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

type CredentialRequest struct {
	Format string   `json:"format,omitempty"`
	Types  []string `json:"types"`
	Proof  JWTProof `json:"proof,omitempty"`
}

type JWTProof struct {
	JWT       string `json:"jwt"`
	ProofType string `json:"proof_type"`
}

type CredentialResponse struct {
	AcceptanceToken string                 `json:"acceptance_token,omitempty"`
	CNonce          string                 `json:"c_nonce,omitempty"`
	CNonceExpiresIn int                    `json:"c_nonce_expires_in,omitempty"`
	Credential      interface{}            `json:"credential"`
	Format          verifiable2.OIDCFormat `json:"format"`
}
