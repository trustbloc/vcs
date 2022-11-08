/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcutil

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

func TestGetContextsFromJSONRaw(t *testing.T) {
	t.Parallel()

	t.Run("get context from raw JSON", func(t *testing.T) {
		tests := []struct {
			name                    string
			credentialFormatOptions json.RawMessage
			result                  int
			err                     string
		}{
			{
				name:   "default without context",
				result: 1,
			},
			{
				name: "override with multiple context",
				credentialFormatOptions: stringToRaw(`{
						"@context": [
								"https://www.w3.org/2018/credentials/v1", 
								"https://www.w3.org/2018/credentials/examples/v1",
								"https://www.w3.org/2018/credentials/examples/v2"
								]
							}
						`),
				result: 3,
			},
			{
				name: "override with single context",
				credentialFormatOptions: stringToRaw(`{
						"@context": "https://www.w3.org/2018/credentials/v1" 
							}
						`),
				result: 1,
			},
			{
				name: "invalid context",
				credentialFormatOptions: stringToRaw(`{
						"@context": [
								"https://www.w3.org/2018/credentials/v1", 
								"https://www.w3.org/2018/credentials/examples/v1"
								https://www.w3.org/2018/credentials/examples/v2
								]
							}
						`),
				err: "invalid character",
			},
			{
				name: "context of unknown type",
				credentialFormatOptions: stringToRaw(`{
						"@context": 1
							}
						`),
				err: "credential context of unknown type",
			},
			{
				name: "context array of unknown type",
				credentialFormatOptions: stringToRaw(`{
						"@context": [{"id":"1233"}]
							}
						`),
				err: "unexpected context type",
			},
			{
				name: "no context in options",
				credentialFormatOptions: stringToRaw(`{
						"xyz": [
								"https://www.w3.org/2018/credentials/v1", 
								"https://www.w3.org/2018/credentials/examples/v1"
								]
							}
						`),
				result: 1,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				ctx, err := GetContextsFromJSONRaw(tc.credentialFormatOptions)

				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				require.NoError(t, err)
				require.Len(t, ctx, tc.result)
			})
		}
	})
}

func TestDecodeTypedIDFromJSONRaw(t *testing.T) {
	t.Parallel()

	t.Run("decode typed ID from raw JSON", func(t *testing.T) {
		tests := []struct {
			name   string
			input  json.RawMessage
			result int
			err    string
		}{
			{
				name:   "default without input",
				result: 0,
			},
			{
				name: "simple type IDs",
				input: stringToRaw(`{
						"id" : "http://example.com",
						"type" : "sample-type"
				}`),
				result: 1,
			},
			{
				name: "multiple type IDs",
				input: stringToRaw(`[
					{"id":"http://example.com/1","type":"sample-type-1"},
					{"id":"http://example.com/2","type":"sample-type-2"}
				]`),
				result: 2,
			},
			{
				name: "invalid raw json format",
				input: stringToRaw(`{[
					{"id":"http://example.com/1","type":"sample-type-1"},
					{"id":"http://example.com/2","type":"sample-type-2"}
				]}`),
				err: "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				tIDs, err := DecodeTypedIDFromJSONRaw(tc.input)

				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				require.NoError(t, err)
				require.Len(t, tIDs, tc.result)
			})
		}
	})
}

func TestUpdateIssuer(t *testing.T) {
	issuerDID := "did:example"
	issuerName := "sample-profile"

	// no issuer in credential
	vc := &verifiable.Credential{}

	UpdateIssuer(vc, issuerDID, issuerName, false)
	require.NotEmpty(t, vc.Issuer)
	require.Equal(t, vc.Issuer.ID, issuerDID)
	require.Equal(t, vc.Issuer.CustomFields["name"], issuerName)

	// issuer in credential
	vc = &verifiable.Credential{Issuer: verifiable.Issuer{
		ID: "sample-issuer-id",
	}}

	UpdateIssuer(vc, issuerDID, issuerName, false)
	require.NotEmpty(t, vc.Issuer)
	require.Equal(t, vc.Issuer.ID, "sample-issuer-id")
	require.Empty(t, vc.Issuer.CustomFields)

	// issuer in credential + profile overwrites issuer
	UpdateIssuer(vc, issuerDID, issuerName, true)
	require.NotEmpty(t, vc.Issuer)
	require.Equal(t, vc.Issuer.ID, issuerDID)
	require.Equal(t, vc.Issuer.CustomFields["name"], issuerName)
}

func TestUpdateSignatureTypeContext(t *testing.T) {
	vc := &verifiable.Credential{Context: []string{DefVCContext}}

	require.Len(t, vc.Context, 1)

	UpdateSignatureTypeContext(vc, vcsverifiable.JSONWebSignature2020)
	require.Len(t, vc.Context, 2)

	UpdateSignatureTypeContext(vc, vcsverifiable.BbsBlsSignature2020)
	require.Len(t, vc.Context, 3)
}

func stringToRaw(s string) json.RawMessage {
	return json.RawMessage([]byte(s))
}
