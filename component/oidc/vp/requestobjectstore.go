/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type RequestObjectStore struct {
	host string
	root string
}

func NewRequestObjectStore(host, root string) *RequestObjectStore {
	return &RequestObjectStore{
		host: host,
		root: root,
	}
}

func (s *RequestObjectStore) Publish(requestObject string) (string, error) {
	fileName := uuid.NewString()
	err := os.WriteFile(filepath.Join(s.root, fileName), []byte(requestObject), 0600)
	if err != nil {
		return "", fmt.Errorf("unable to write file: %w", err)
	}

	return url.JoinPath(s.host, fileName)
}

func (s *RequestObjectStore) Remove(fileName string) error {
	return os.RemoveAll(filepath.Join(s.root, fileName))
}
