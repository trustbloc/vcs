/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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

type IDTokenClaims struct {
	VPToken IDTokenVPToken `json:"_vp_token"`
	Nonce   string         `json:"nonce"`
	Exp     int64          `json:"exp"`
	Iss     string         `json:"iss"`
}

type VPTokenClaims struct {
	VP    *verifiable.Presentation `json:"vp"`
	Nonce string                   `json:"nonce"`
	Exp   int64                    `json:"exp"`
	Iss   string                   `json:"iss"`
}

type InitiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxId                 string `json:"txID"`
}
