/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package arieskmsstore

import (
	"context"
	"encoding/json"
	"path"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/internal/logfields"
)

var logger = log.New("aries-kms-secret-store")

type Store struct {
	client Client
	prefix string
}

func NewStore(
	client Client,
	keyPrefix string,
) *Store {
	logger.Info("creating new aries-kms-secret-store", logfields.WithIDToken(keyPrefix)))

	return &Store{
		client: client,
		prefix: keyPrefix,
	}
}

type DataWrapper struct {
	ID  string `json:"ID"`
	Bin []byte `json:"bin"`
}

func (s *Store) GetPath(
	keySetID string,
) string {
	return path.Join(s.prefix, keySetID)
}

func (s *Store) Put(keysetID string, key []byte) error {
	data, err := json.Marshal(DataWrapper{
		ID:  keysetID,
		Bin: key,
	})
	if err != nil {
		return err
	}

	_, err = s.client.PutSecretValue(context.Background(), &secretsmanager.PutSecretValueInput{
		SecretId:     lo.ToPtr(s.GetPath(keysetID)),
		SecretBinary: data,
		SecretString: nil,
	})

	return err
}

func (s *Store) Get(keysetID string) ([]byte, error) {
	out, err := s.client.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: lo.ToPtr(s.GetPath(keysetID)),
	})
	if err != nil {
		return nil, err
	}

	var wrapper DataWrapper
	if err = json.Unmarshal(out.SecretBinary, &wrapper); err != nil {
		return nil, err
	}

	return wrapper.Bin, nil
}

func (s *Store) Delete(keysetID string) error {
	_, err := s.client.DeleteSecret(context.Background(), &secretsmanager.DeleteSecretInput{
		SecretId: lo.ToPtr(s.GetPath(keysetID)),
	})

	return err
}
