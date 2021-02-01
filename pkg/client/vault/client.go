/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	hubKMSCreateKeyStorePath = "/kms/keystores"

	headerLocation        = "Location"
	headerXRootCapability = "X-ROOTCAPABILITY"
)

// KeyManager KMS alias.
type KeyManager kms.KeyManager

// HTTPClient interface for the http client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client vault`s client.
type Client struct {
	remoteKMSURL string
	kms          KeyManager
	crypto       crypto.Crypto
	edvClient    *edv.Client
	httpClient   HTTPClient
}

// Opt represents Client`s option.
type Opt func(*Client)

// WithHTTPClient allows providing HTTP client.
func WithHTTPClient(client HTTPClient) Opt {
	return func(vault *Client) {
		vault.httpClient = client
	}
}

// NewClient creates a new vault client.
func NewClient(kmsURL, edvURL string, kmsClient kms.KeyManager, opts ...Opt) (*Client, error) {
	cryptoService, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("tinkcrypto new: %w", err)
	}

	client := &Client{
		remoteKMSURL: kmsURL,
		kms:          kmsClient,
		crypto:       cryptoService,
		// TODO: EDV client does not support injection own HTTP client
		edvClient:  edv.New(edvURL),
		httpClient: &http.Client{},
	}

	for _, fn := range opts {
		fn(client)
	}

	return client, nil
}

// CreateVault creates a new vault and KMS store bases on generated DIDKey.
func (c *Client) CreateVault() (*CreatedVault, error) {
	didKey, err := c.createDIDKey()
	if err != nil {
		return nil, fmt.Errorf("create DID key: %w", err)
	}

	kmsLoc, err := c.createKeyStore(didKey)
	if err != nil {
		return nil, fmt.Errorf("create key store: %w", err)
	}

	edvLoc, err := c.createDataVault(didKey)
	if err != nil {
		return nil, fmt.Errorf("create data vault: %w", err)
	}

	return &CreatedVault{
		ID:  didKey,
		KMS: kmsLoc,
		EDV: edvLoc,
	}, nil
}

// CreatedVault represents success response of CreateVault function.
type CreatedVault struct {
	ID  string    `json:"id"`
	EDV *Location `json:"edv"`
	KMS *Location `json:"kms"`
}

// Location consists of URI and zcap capability.
type Location struct {
	URI  string `json:"uri"`
	ZCAP string `json:"zcap"`
}

func (c *Client) createDIDKey() (string, error) {
	sig, err := signature.NewCryptoSigner(c.crypto, c.kms, kms.ED25519)
	if err != nil {
		return "", fmt.Errorf("new crypto signer: %w", err)
	}

	_, didKey := fingerprint.CreateDIDKey(sig.PublicKeyBytes())

	return didKey, nil
}

func (c *Client) createDataVault(didKey string) (*Location, error) {
	vaultURI, rawCapability, err := c.edvClient.CreateDataVault(&models.DataVaultConfiguration{
		Controller:  didKey,
		ReferenceID: uuid.New().String(),
		KEK:         models.IDTypePair{ID: uuid.New().URN(), Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: uuid.New().URN(), Type: "Sha256HmacKey2019"},
	})
	if err != nil {
		return nil, fmt.Errorf("create data vault: %w", err)
	}

	capability, err := zcapld.ParseCapability(rawCapability)
	if err != nil {
		return nil, fmt.Errorf("parse capability: %w", err)
	}

	compressedZcap, err := compressZCAP(capability)
	if err != nil {
		return nil, fmt.Errorf("compress zcap: %w", err)
	}

	return &Location{URI: vaultURI, ZCAP: compressedZcap}, nil
}

func (c *Client) createKeyStore(didKey string) (*Location, error) {
	payload := bytes.NewBuffer([]byte(fmt.Sprintf(`{"controller": %q}`, didKey)))

	// TODO: use KMS from Aries after it will have the ability to return "X-ROOTCAPABILITY"
	req, err := http.NewRequest(http.MethodPost, c.remoteKMSURL+hubKMSCreateKeyStorePath, payload)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http Do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	_, err = io.Copy(ioutil.Discard, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("copy: %w", err)
	}

	return &Location{
		URI:  resp.Header.Get(headerLocation),
		ZCAP: resp.Header.Get(headerXRootCapability),
	}, nil
}

func compressZCAP(zcap *zcapld.Capability) (string, error) {
	raw, err := json.Marshal(zcap)
	if err != nil {
		return "", err
	}

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}
