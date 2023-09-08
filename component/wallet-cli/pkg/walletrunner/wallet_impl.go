/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"
)

type walletImpl struct {
	credStore storage.Store
	ldLoader  ld.DocumentLoader
	storeLock sync.RWMutex
}

func (w *walletImpl) Open(string) string {
	return "token"
}

func (w *walletImpl) Close() bool {
	return true
}

const credentialTag = "credential"

func (w *walletImpl) Add(content json.RawMessage) error {
	key, err := getContentID(content)
	if err != nil {
		return err
	}

	w.storeLock.Lock()
	defer w.storeLock.Unlock()

	err = w.credStore.Put(key, content, storage.Tag{Name: credentialTag})
	if err != nil {
		return err
	}

	return nil
}

type contentID struct {
	ID string `json:"id"`
}

func getContentID(content json.RawMessage) (string, error) {
	key, err := getJWTContentID(string(content))
	if err == nil && strings.TrimSpace(key) != "" {
		return key, nil
	}

	var cid contentID
	if err := json.Unmarshal(content, &cid); err != nil {
		return "", fmt.Errorf("failed to read content to be saved : %w", err)
	}

	key = cid.ID
	if strings.TrimSpace(key) == "" {
		// use document hash as key to avoid duplicates if id is missing
		digest := sha256.Sum256(content)

		key = hex.EncodeToString(digest[0:])
	}

	return key, nil
}

type hasJTI struct {
	JTI string `json:"jti"`
}

func getJWTContentID(jwtStr string) (string, error) {
	parts := strings.Split(unQuote(jwtStr), ".")
	if len(parts) != 3 { // nolint: gomnd
		return "", nil // assume not a jwt
	}

	credBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode base64 JWT data: %w", err)
	}

	cred := &hasJTI{}

	err = json.Unmarshal(credBytes, cred)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JWT data: %w", err)
	}

	if cred.JTI == "" {
		return "", fmt.Errorf("JWT data has no ID")
	}

	return cred.JTI, nil
}

func unQuote(s string) string {
	if len(s) <= 1 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}

	return s
}

func (w *walletImpl) GetAll() (map[string]json.RawMessage, error) {
	w.storeLock.RLock()
	defer w.storeLock.RUnlock()

	iter, err := w.credStore.Query(credentialTag)
	if err != nil {
		return nil, err
	}

	result := make(map[string]json.RawMessage)

	for {
		ok, err := iter.Next()
		if err != nil {
			return nil, err
		}

		if !ok {
			break
		}

		key, err := iter.Key()
		if err != nil {
			return nil, err
		}

		val, err := iter.Value()
		if err != nil {
			return nil, err
		}

		result[key] = val
	}

	return result, nil
}

func (w *walletImpl) Query(pdBytes []byte) ([]*verifiable.Presentation, error) {
	vcContents, err := w.GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}

	if len(vcContents) == 0 {
		return nil, errors.New("no result found")
	}

	creds, err := parseCredentialContents(vcContents, w.ldLoader)
	if err != nil {
		return nil, err
	}

	var presDefinition presexch.PresentationDefinition

	err = json.Unmarshal(pdBytes, &presDefinition)
	if err != nil {
		return nil, err
	}

	result, err := presDefinition.CreateVP(creds, w.ldLoader, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(w.ldLoader))

	if errors.Is(err, presexch.ErrNoCredentials) {
		return nil, errors.New("no result found")
	}

	if err != nil {
		return nil, err
	}

	return []*verifiable.Presentation{result}, nil
}

func parseCredentialContents(
	raws map[string]json.RawMessage,
	documentLoader ld.DocumentLoader,
) ([]*verifiable.Credential, error) {
	var result []*verifiable.Credential

	for _, raw := range raws {
		vc, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(documentLoader))
		if err != nil {
			return nil, err
		}

		result = append(result, vc)
	}

	return result, nil
}
