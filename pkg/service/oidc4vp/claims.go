/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

func (tm *TxManager) EncryptClaims(data *ReceivedClaims) (*ClaimData, error) {
	bytesData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	encrypted, nonce, err := tm.crypto.Encrypt(bytesData, nil, tm.cryptoKeyID)
	if err != nil {
		return nil, err
	}

	return &ClaimData{
		Encrypted:      encrypted,
		EncryptedNonce: nonce,
	}, nil
}

func (tm *TxManager) DecryptClaims(data *ClaimData) (*ReceivedClaims, error) {
	resp, err := tm.crypto.Decrypt(nil, data.Encrypted, data.EncryptedNonce, tm.cryptoKeyID)
	if err != nil {
		return nil, err
	}

	raw := receivedClaimsRaw{}
	if err = json.Unmarshal(resp, &raw); err != nil {
		return nil, fmt.Errorf("can not unmarshal to receivedClaimsRaw, err: %w", err)
	}

	final := &ReceivedClaims{
		Credentials: map[string]*verifiable.Credential{},
	}

	for k, v := range raw.Credentials {
		parsed, parseErr := verifiable.ParseCredential(v,
			//verifiable.WithJSONLDDocumentLoader(docLoader),
			verifiable.WithDisabledProofCheck())

		if parseErr != nil {
			return nil, fmt.Errorf("received claims deserialize failed: %w", parseErr)
		}
		final.Credentials[k] = parsed
	}

	return final, nil
}
