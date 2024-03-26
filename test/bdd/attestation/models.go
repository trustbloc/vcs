/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

type AttestWalletInitRequest struct {
	Payload map[string]interface{} `json:"payload"`
}

type AttestWalletInitResponse struct {
	Challenge string `json:"challenge"`
	SessionID string `json:"session_id"`
}

type AttestWalletCompleteRequest struct {
	AssuranceLevel string `json:"assurance_level"`
	Proof          Proof  `json:"proof"`
	SessionID      string `json:"session_id"`
}

type Proof struct {
	Jwt       string `json:"jwt,omitempty"`
	ProofType string `json:"proof_type"`
}

type JwtProofClaims struct {
	Issuer   string `json:"iss,omitempty"`
	Audience string `json:"aud,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
}

type AttestWalletCompleteResponse struct {
	WalletAttestationVC string `json:"wallet_attestation_vc"`
}

type IssueCredentialData struct {
	Credential interface{} `json:"credential"`
}
