/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"time"

	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"
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
	// ScopeAdditionalClaims stores claims retrieved using custom scope.
	ScopeAdditionalClaims map[string]Claims `json:"_scope,omitempty"` //custom scope -> additional claims
	VPToken               IDTokenVPToken    `json:"_vp_token"`
	AttestationVP         string            `json:"_attestation_vp"`
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

type PerfInfo struct {
	FetchRequestObject         time.Duration `json:"vp_fetch_request_object"`
	VerifyAuthorizationRequest time.Duration `json:"vp_verify_authorization_request"`
	QueryCredentialFromWallet  time.Duration `json:"vp_query_credential_from_wallet"`
	CreateAuthorizedResponse   time.Duration `json:"vp_create_authorized_response"`
	SendAuthorizedResponse     time.Duration `json:"vp_send_authorized_response"`
}
