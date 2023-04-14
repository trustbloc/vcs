/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"encoding/json"
)

func (s *Service) EncryptClaims(ctx context.Context, data map[string]interface{}) (*ClaimData, error) {
	bytesData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	encrypted, err := s.dataProtector.Encrypt(ctx, bytesData)
	if err != nil {
		return nil, err
	}

	return &ClaimData{
		EncryptedData: encrypted,
	}, nil
}

func (s *Service) DecryptClaims(ctx context.Context, data *ClaimData) (map[string]interface{}, error) {
	resp, err := s.dataProtector.Decrypt(ctx, data.EncryptedData)
	if err != nil {
		return nil, err
	}

	finalMap := map[string]interface{}{}
	if err = json.Unmarshal(resp, &finalMap); err != nil {
		return nil, err
	}

	return finalMap, nil
}
