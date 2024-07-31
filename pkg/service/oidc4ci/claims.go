/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func (s *Service) EncryptClaims(ctx context.Context, data map[string]interface{}) (*ClaimData, error) {
	return encryptClaims(ctx, data, s.dataProtector)
}

func (s *Service) DecryptClaims(ctx context.Context, data *ClaimData) (map[string]interface{}, error) {
	return decryptClaims(ctx, data, s.dataProtector)
}

func encryptClaims(ctx context.Context, data map[string]interface{}, protector dataProtector) (*ClaimData, error) {
	bytesData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	encrypted, err := protector.Encrypt(ctx, bytesData)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.DataProtectorComponent, "Encrypt", err)
	}

	return &ClaimData{
		EncryptedData: encrypted,
	}, nil
}

func decryptClaims(ctx context.Context, data *ClaimData, protector dataProtector) (map[string]interface{}, error) {
	resp, err := protector.Decrypt(ctx, data.EncryptedData)
	if err != nil {
		return nil, resterr.NewSystemError(resterr.DataProtectorComponent, "Decrypt", err)
	}

	finalMap := map[string]interface{}{}
	if err = json.Unmarshal(resp, &finalMap); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return finalMap, nil
}
