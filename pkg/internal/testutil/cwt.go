/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/verifiable"
	cwt2 "github.com/trustbloc/vc-go/verifiable/cwt"
	"github.com/veraison/go-cose"
)

func SignedClaimsCWTWithExistingPrivateKey(
	t *testing.T,
	verMethodDIDKeyID string,
	signer api.FixedKeySigner,
	claims interface{},
) string {
	t.Helper()

	coseAlgo, err := verifiable.KeyTypeToCWSAlgo(kms.ED25519Type)
	assert.NoError(t, err)

	payload, err := cbor.Marshal(claims)
	assert.NoError(t, err)

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: coseAlgo,
				cose.HeaderLabelKeyID:     []byte(verMethodDIDKeyID),
			},
			Unprotected: cose.UnprotectedHeader{
				cose.HeaderLabelContentType: "application/vc+ld+json+cose",
			},
		},
		Payload: payload,
	}

	signData, err := cwt2.GetProofValue(msg)
	assert.NoError(t, err)

	signed, err := signer.Sign(signData)
	assert.NoError(t, err)

	msg.Signature = signed

	final, err := cbor.Marshal(msg)
	assert.NoError(t, err)

	return hex.EncodeToString(final)
}
