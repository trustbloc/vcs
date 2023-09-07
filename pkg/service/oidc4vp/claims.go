/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"
)

func (tm *TxManager) EncryptClaims(ctx context.Context, data *ReceivedClaims) (*ClaimData, error) {
	if data == nil {
		return nil, nil //nolint:nilnil
	}
	raw, err := tm.ClaimsToClaimsRaw(data)
	if err != nil {
		return nil, err
	}

	bytesData, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	encrypted, err := tm.dataProtector.Encrypt(ctx, bytesData)
	if err != nil {
		return nil, err
	}

	return &ClaimData{
		EncryptedData: encrypted,
	}, nil
}

func (tm *TxManager) ClaimsToClaimsRaw(data *ReceivedClaims) (*ReceivedClaimsRaw, error) {
	if data == nil {
		return nil, nil //nolint:nilnil
	}

	raw := &ReceivedClaimsRaw{
		Credentials: map[string][]byte{},
	}
	for key, cred := range data.Credentials {
		cl, err := json.Marshal(cred)
		if err != nil {
			return nil, fmt.Errorf("serialize received claims %w", err)
		}

		raw.Credentials[key] = cl
	}

	return raw, nil
}

func (tm *TxManager) DecryptClaims(ctx context.Context, data *ClaimData) (*ReceivedClaims, error) {
	if data == nil { // can happen for vp
		return nil, nil //nolint:nilnil
	}

	resp, err := tm.dataProtector.Decrypt(ctx, data.EncryptedData)
	if err != nil {
		return nil, err
	}

	raw := ReceivedClaimsRaw{}
	if err = json.Unmarshal(resp, &raw); err != nil {
		return nil, fmt.Errorf("can not unmarshal to ReceivedClaimsRaw, err: %w", err)
	}

	final := &ReceivedClaims{
		Credentials: map[string]*verifiable.Credential{},
	}

	for k, v := range raw.Credentials {
		parsed, parseErr := verifiable.ParseCredential(v,
			verifiable.WithJSONLDDocumentLoader(tm.docLoader),
			verifiable.WithDisabledProofCheck())

		if parseErr != nil {
			return nil, fmt.Errorf("received claims deserialize failed: %w", parseErr)
		}
		final.Credentials[k] = parsed
	}

	return final, nil
}
