/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package chs

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"

	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
)

const (
	profilesEndpoint = "/hubstore/profiles"
)

func newUser(baseURL string, tlsConfig *tls.Config) (*user, error) {
	k, err := localkms.New(
		"local-lock://test/key-uri/",
		&mockKMSProvider{
			sp: mem.NewProvider(),
			sl: &noop.NoLock{},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init kms: %w", err)
	}

	c, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("failed to init tink crypto: %w", err)
	}

	return &user{
		baseURL: baseURL,
		kms:     k,
		crypto:  c,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

type user struct {
	kms        kms.KeyManager
	crypto     crypto.Crypto
	profile    *operation.Profile
	httpClient *http.Client
	controller string
	baseURL    string
}

func (u *user) requestNewProfile() error {
	signer, err := signature.NewCryptoSigner(u.crypto, u.kms, kms.ED25519)
	if err != nil {
		return fmt.Errorf("failed to create a new signer: %w", err)
	}

	u.controller = didKeyURL(signer.PublicKeyBytes())

	payload, err := json.Marshal(&operation.Profile{
		Controller: u.controller,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request payload: %w", err)
	}

	target := u.baseURL + profilesEndpoint

	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	response, err := u.httpClient.Do(request) // nolint:bodyclose // closed with utility function below
	if err != nil {
		return fmt.Errorf("failed to execute request %s: %w", target, err)
	}

	defer bddutil.CloseResponseBody(response.Body)

	if response.StatusCode != http.StatusCreated {
		msg := &model.ErrorResponse{}

		err = json.NewDecoder(response.Body).Decode(msg)
		if err != nil {
			fmt.Printf("ERROR - failed to read error response body: %s", err.Error())
		}

		return fmt.Errorf("unexpected response: code=%d msg=%+v", response.StatusCode, msg)
	}

	u.profile = &operation.Profile{}

	err = json.NewDecoder(response.Body).Decode(u.profile)
	if err != nil {
		return fmt.Errorf("failed to decode response payload: %w", err)
	}

	return nil
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

type mockKMSProvider struct {
	sp ariesstorage.Provider
	sl secretlock.Service
}

func (m *mockKMSProvider) StorageProvider() ariesstorage.Provider {
	return m.sp
}

func (m *mockKMSProvider) SecretLock() secretlock.Service {
	return m.sl
}
