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
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"
)

const storeName = "vault"

// Vault defines vault client interface.
type Vault interface {
	CreateVault() (*CreatedVault, error)
	SaveDoc(vaultID, id string, content interface{}) (*DocumentMetadata, error)
}

// KeyManager KMS alias.
type KeyManager kms.KeyManager

// HTTPClient interface for the http client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CreatedVault represents success response of CreateVault function.
type CreatedVault struct {
	ID string `json:"id"`
	*Authorization
}

// Authorization consists of info needed for the authorization.
type Authorization struct {
	EDV *Location `json:"edv"`
	KMS *Location `json:"kms"`
}

// Location consists of URI and zcap capability.
type Location struct {
	URI       string `json:"uri"`
	AuthToken string `json:"authToken"`
}

// DocumentMetadata represents document`s metadata.
type DocumentMetadata struct {
	ID  string `json:"docID"`
	URI string `json:"edvDocURI"`
}

// Client vault`s client.
type Client struct {
	remoteKMSURL string
	edvHost      string
	kms          KeyManager
	crypto       crypto.Crypto
	edvClient    *edv.Client
	httpClient   HTTPClient
	store        storage.Store
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
func NewClient(kmsURL, edvURL string, kmsClient kms.KeyManager, db storage.Provider, opts ...Opt) (*Client, error) {
	cryptoService, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("tinkcrypto new: %w", err)
	}

	u, err := url.Parse(edvURL)
	if err != nil {
		return nil, fmt.Errorf("url parse: %w", err)
	}

	store, err := db.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	client := &Client{
		remoteKMSURL: kmsURL,
		edvHost:      u.Host,
		kms:          kmsClient,
		crypto:       cryptoService,
		store:        store,
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

	kmsURI, kmsZCAP, err := webkms.CreateKeyStore(c.httpClient, c.remoteKMSURL, didKey, "")
	if err != nil {
		return nil, fmt.Errorf("create key store: %w", err)
	}

	edvLoc, err := c.createDataVault(didKey)
	if err != nil {
		return nil, fmt.Errorf("create data vault: %w", err)
	}

	auth := &Authorization{
		KMS: &Location{
			URI:       kmsURI,
			AuthToken: kmsZCAP,
		},
		EDV: edvLoc,
	}

	err = c.saveAuthorization(didKey, auth)
	if err != nil {
		return nil, fmt.Errorf("save authorization: %w", err)
	}

	return &CreatedVault{
		ID:            didKey,
		Authorization: auth,
	}, nil
}

// SaveDoc saves a document by encrypting it and storing it in the vault.
func (c *Client) SaveDoc(vaultID, id string, content interface{}) (*DocumentMetadata, error) {
	auth, err := c.getAuthorization(vaultID)
	if err != nil {
		return nil, fmt.Errorf("get authorization: %w", err)
	}

	encContent, err := encryptContent(c.webKMS(vaultID, auth.KMS), c.webCrypto(vaultID, auth.KMS), content)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}

	edvVaultID := lastElm(auth.EDV.URI, "/")

	res, err := c.edvClient.CreateDocument(edvVaultID, &models.EncryptedDocument{
		ID:  id,
		JWE: []byte(encContent),
	}, edv.WithRequestHeader(c.edvSign(vaultID, auth.EDV)))
	if err == nil {
		return &DocumentMetadata{URI: res, ID: lastElm(res, "/")}, nil
	}

	if !strings.HasSuffix(err.Error(), messages.ErrDuplicateDocument.Error()+".") {
		return nil, fmt.Errorf("create document: %w", err)
	}

	err = c.edvClient.UpdateDocument(edvVaultID, id, &models.EncryptedDocument{
		ID:  id,
		JWE: []byte(encContent),
	}, edv.WithRequestHeader(c.edvSign(vaultID, auth.EDV)))
	if err != nil {
		return nil, fmt.Errorf("update document: %w", err)
	}

	return &DocumentMetadata{ID: id, URI: buildEDVURI(c.edvHost, edvVaultID, id)}, nil
}

func (c *Client) saveAuthorization(id string, auth *Authorization) error {
	src, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.store.Put(fmt.Sprintf("auth_%s", id), src)
}

func (c *Client) getAuthorization(id string) (*Authorization, error) {
	src, err := c.store.Get(fmt.Sprintf("auth_%s", id))
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}

	var auth *Authorization

	err = json.Unmarshal(src, &auth)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return auth, nil
}

func (c *Client) webKMS(controller string, auth *Location) *webkms.RemoteKMS {
	return webkms.New(
		c.remoteKMSURL+auth.URI,
		c.httpClient,
		webkms.WithHeaders(c.kmsSign(controller, auth)),
	)
}

func (c *Client) webCrypto(controller string, auth *Location) *webcrypto.RemoteCrypto {
	return webcrypto.New(
		c.remoteKMSURL+auth.URI,
		c.httpClient,
		webkms.WithHeaders(c.kmsSign(controller, auth)),
	)
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

	return &Location{URI: vaultURI, AuthToken: compressedZcap}, nil
}

func (c *Client) edvSign(controller string, auth *Location) func(req *http.Request) (*http.Header, error) {
	return func(req *http.Request) (*http.Header, error) {
		action := "write"
		if req.Method == http.MethodGet {
			action = "read"
		}

		return c.sign(req, controller, action, auth.AuthToken)
	}
}

func (c *Client) kmsSign(controller string, auth *Location) func(req *http.Request) (*http.Header, error) {
	return func(req *http.Request) (*http.Header, error) {
		action, err := operation.CapabilityInvocationAction(req)
		if err != nil {
			return nil, fmt.Errorf("capability invocation action: %w", err)
		}

		return c.sign(req, controller, action, auth.AuthToken)
	}
}

func (c *Client) sign(req *http.Request, controller, action, zcap string) (*http.Header, error) {
	req.Header.Set(
		zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`, zcap, action),
	)

	hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
	hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
		Crypto: c.crypto,
		KMS:    c.kms,
	})

	err := hs.Sign(controller, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign http request: %w", err)
	}

	return &req.Header, nil
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

func lastElm(s, sep string) string {
	all := strings.Split(s, sep)

	return all[len(all)-1]
}

func buildEDVURI(h, vid, did string) string {
	return fmt.Sprintf("%s/encrypted-data-vaults/%s/documents/%s", h, vid, did)
}

func encryptContent(wKMS KeyManager, wCrypto crypto.Crypto, content interface{}) (string, error) {
	src, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	_, kidURL, err := wKMS.Create(kms.NISTP256ECDHKW)
	if err != nil {
		return "", fmt.Errorf("create: %w", err)
	}

	pubKeyBytes, err := wKMS.ExportPubKeyBytes(lastElm(kidURL.(string), "/"))
	if err != nil {
		return "", fmt.Errorf("export pubKey bytes: %w", err)
	}

	var ecPubKey *crypto.PublicKey

	err = json.Unmarshal(pubKeyBytes, &ecPubKey)
	if err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, jose.A256GCMALG, "", nil,
		[]*crypto.PublicKey{ecPubKey}, wCrypto)
	if err != nil {
		return "", fmt.Errorf("new JWE encrypt: %w", err)
	}

	jwe, err := encrypter.Encrypt(src)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return jwe.FullSerialize(json.Marshal)
}
