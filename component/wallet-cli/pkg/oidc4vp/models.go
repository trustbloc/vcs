/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"time"

	"github.com/trustbloc/vc-go/presexch"
)

type RequestObject struct {
	JTI                    string                           `json:"jti"`
	IAT                    int64                            `json:"iat"`
	ResponseType           string                           `json:"response_type"`
	ResponseMode           string                           `json:"response_mode"`
	ResponseURI            string                           `json:"response_uri"`
	Scope                  string                           `json:"scope"`
	Nonce                  string                           `json:"nonce"`
	ClientID               string                           `json:"client_id"`
	State                  string                           `json:"state"`
	Exp                    int64                            `json:"exp"`
	ClientMetadata         *ClientMetadata                  `json:"client_metadata"`
	PresentationDefinition *presexch.PresentationDefinition `json:"presentation_definition"`
}

type ClientMetadata struct {
	ClientName                  string           `json:"client_name"`
	ClientPurpose               string           `json:"client_purpose"`
	SubjectSyntaxTypesSupported []string         `json:"subject_syntax_types_supported"`
	VPFormats                   *presexch.Format `json:"vp_formats"`
}

type Claims = map[string]interface{}

type IDTokenClaims struct {
	// ScopeAdditionalClaims stores claims retrieved using custom scope.
	ScopeAdditionalClaims map[string]Claims `json:"_scope,omitempty"` //custom scope -> additional claims
	AttestationVP         string            `json:"_attestation_vp"`
	Nonce                 string            `json:"nonce"`
	Exp                   int64             `json:"exp"`
	Iss                   string            `json:"iss"`
	Aud                   string            `json:"aud"`
	Sub                   string            `json:"sub"`
	Nbf                   int64             `json:"nbf"`
	Iat                   int64             `json:"iat"`
	Jti                   string            `json:"jti"`
	Attachments           map[string]string `json:"_attachments"`
}

type PerfInfo struct {
	FetchRequestObject         time.Duration `json:"vp_fetch_request_object"`
	VerifyAuthorizationRequest time.Duration `json:"vp_verify_authorization_request"`
	QueryCredentialFromWallet  time.Duration `json:"vp_query_credential_from_wallet"`
	CreateAuthorizedResponse   time.Duration `json:"vp_create_authorized_response"`
	SendAuthorizedResponse     time.Duration `json:"vp_send_authorized_response"`
	VcsVPFlowDuration          time.Duration `json:"_vcs_vp_flow_duration"`
}
