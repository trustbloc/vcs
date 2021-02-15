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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"
)

const storeName = "vault"

// Vault defines vault client interface.
type Vault interface {
	CreateVault() (*CreatedVault, error)
	SaveDoc(vaultID, id string, content interface{}) (*DocumentMetadata, error)
	GetDocMetadata(vaultID, docID string) (*DocumentMetadata, error)
	CreateAuthorization(vaultID, requestingParty string, scope *Scope) (*CreatedAuthorization, error)
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

// CreatedAuthorization represents success response of CreateAuthorization function.
type CreatedAuthorization struct {
	ID              string  `json:"id"`
	Scope           *Scope  `json:"scope"`
	RequestingParty string  `json:"requestingParty"`
	Tokens          *Tokens `json:"authTokens"`
}

// Tokens zcap tokens.
type Tokens struct {
	EDV string `json:"edv"`
	KMS string `json:"kms"`
}

// Scope represents authorization request.
type Scope struct {
	Target     string   `json:"target,omitempty"`
	TargetAttr string   `json:"targetAttr,omitempty"`
	Actions    []string `json:"actions,omitempty"`
	Caveats    []Caveat `json:"caveats,omitempty"`
}

// Caveat for the Scope request.
type Caveat struct {
	Type     string `json:"type,omitempty"`
	Duration string `json:"duration,omitempty"`
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
		httpClient: &http.Client{
			Timeout: time.Minute,
		},
	}

	for _, fn := range opts {
		fn(client)
	}

	client.edvClient = edv.New(edvURL, edv.WithHTTPClient(client.httpClient))

	return client, nil
}

// CreateVault creates a new vault and KMS store bases on generated DIDKey.
func (c *Client) CreateVault() (*CreatedVault, error) {
	didKey, didURL, kid, err := c.createDIDKey()
	if err != nil {
		return nil, fmt.Errorf("create DID key: %w", err)
	}

	kmsURI, kmsZCAP, err := webkms.CreateKeyStore(c.httpClient, c.remoteKMSURL, didURL, "")
	if err != nil {
		return nil, fmt.Errorf("create key store: %w", err)
	}

	edvLoc, err := c.createDataVault(didURL)
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

	err = c.saveVaultInfo(didKey, &vaultInfo{Auth: auth, KID: kid})
	if err != nil {
		return nil, fmt.Errorf("save vault info: %w", err)
	}

	return &CreatedVault{
		ID:            didKey,
		Authorization: auth,
	}, nil
}

// CreateAuthorization creates a new authorization.
// nolint: funlen,gocyclo
func (c *Client) CreateAuthorization(vaultID, requestingParty string, scope *Scope) (*CreatedAuthorization, error) {
	info, err := c.getVaultInfo(vaultID)
	if err != nil {
		return nil, fmt.Errorf("get vault info: %w", err)
	}

	kh, err := c.kms.Get(info.KID)
	if err != nil {
		return nil, fmt.Errorf("kms get: %w", err)
	}

	kmsCapability, err := uncompressZCAP(info.Auth.KMS.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("kms uncompressZCAP: %w", err)
	}

	didURL, err := toDidURL(vaultID)
	if err != nil {
		return nil, fmt.Errorf("to DidURL: %w", err)
	}

	requestingPartyDidURL, err := toDidURL(requestingParty)
	if err != nil {
		return nil, fmt.Errorf("requesting party to DidURL: %w", err)
	}

	kmsNewCapability, err := zcapld.NewCapability(&zcapld.Signer{
		SignatureSuite:     ed25519signature2018.New(suite.WithSigner(newSigner(c.crypto, kh))),
		SuiteType:          ed25519signature2018.SignatureType,
		VerificationMethod: didURL,
	}, zcapld.WithParent(kmsCapability.ID), zcapld.WithInvoker(requestingPartyDidURL),
		zcapld.WithAllowedActions("unwrap"),
		zcapld.WithInvocationTarget(kmsCapability.InvocationTarget.ID, kmsCapability.InvocationTarget.Type),
		zcapld.WithCapabilityChain(kmsCapability.ID))
	if err != nil {
		return nil, fmt.Errorf("kms new capability: %w", err)
	}

	kmsCompressedCapability, err := compressZCAP(kmsNewCapability)
	if err != nil {
		return nil, fmt.Errorf("kms compressZCAP: %w", err)
	}

	edvCapability, err := uncompressZCAP(info.Auth.EDV.AuthToken)
	if err != nil {
		return nil, fmt.Errorf("edv uncompressZCAP: %w", err)
	}

	edvNewCapability, err := zcapld.NewCapability(&zcapld.Signer{
		SignatureSuite:     ed25519signature2018.New(suite.WithSigner(newSigner(c.crypto, kh))),
		SuiteType:          ed25519signature2018.SignatureType,
		VerificationMethod: didURL,
	}, zcapld.WithParent(edvCapability.ID), zcapld.WithInvoker(requestingPartyDidURL),
		zcapld.WithAllowedActions(scope.Actions...),
		zcapld.WithInvocationTarget(edvCapability.InvocationTarget.ID, edvCapability.InvocationTarget.Type),
		zcapld.WithCapabilityChain(edvCapability.Parent, edvCapability.ID))
	if err != nil {
		return nil, fmt.Errorf("edv new capability: %w", err)
	}

	edvCompressedCapability, err := compressZCAP(edvNewCapability)
	if err != nil {
		return nil, fmt.Errorf("edv compressZCAP: %w", err)
	}

	return &CreatedAuthorization{
		ID:              uuid.New().String(),
		Scope:           scope,
		RequestingParty: requestingParty,
		Tokens: &Tokens{
			KMS: kmsCompressedCapability,
			EDV: edvCompressedCapability,
		},
	}, nil
}

// GetDocMetadata returns document`s metadata.
func (c *Client) GetDocMetadata(vaultID, docID string) (*DocumentMetadata, error) {
	info, err := c.getVaultInfo(vaultID)
	if err != nil {
		return nil, fmt.Errorf("get vault info: %w", err)
	}

	edvVaultID := lastElm(info.Auth.EDV.URI, "/")

	eID, err := c.getIDAlias(docID)
	if err != nil {
		return nil, fmt.Errorf("get alias: %w", err)
	}

	_, err = c.edvClient.ReadDocument(edvVaultID, eID, edv.WithRequestHeader(c.edvSign(vaultID, info.Auth.EDV)))
	if err != nil {
		return nil, fmt.Errorf("read document: %w", err)
	}

	return &DocumentMetadata{ID: docID, URI: buildEDVURI(c.edvHost, edvVaultID, eID)}, nil
}

// SaveDoc saves a document by encrypting it and storing it in the vault.
func (c *Client) SaveDoc(vaultID, id string, content interface{}) (*DocumentMetadata, error) {
	info, err := c.getVaultInfo(vaultID)
	if err != nil {
		return nil, fmt.Errorf("get vault info: %w", err)
	}

	eID, err := c.getIDAlias(id)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("get alias: %w", err)
	}

	if errors.Is(err, storage.ErrDataNotFound) {
		eID, err = c.createIDAlias(id)
		if err != nil {
			return nil, fmt.Errorf("create alias: %w", err)
		}
	}

	encContent, err := encryptContent(c.webKMS(vaultID, info.Auth.KMS), c.webCrypto(vaultID, info.Auth.KMS), content)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}

	edvVaultID := lastElm(info.Auth.EDV.URI, "/")

	res, err := c.edvClient.CreateDocument(edvVaultID, &models.EncryptedDocument{
		ID:  eID,
		JWE: []byte(encContent),
	}, edv.WithRequestHeader(c.edvSign(vaultID, info.Auth.EDV)))
	if err == nil {
		return &DocumentMetadata{URI: res, ID: id}, nil
	}

	if !strings.HasSuffix(err.Error(), messages.ErrDuplicateDocument.Error()+".") {
		return nil, fmt.Errorf("create document: %w", err)
	}

	err = c.edvClient.UpdateDocument(edvVaultID, eID, &models.EncryptedDocument{
		ID:  eID,
		JWE: []byte(encContent),
	}, edv.WithRequestHeader(c.edvSign(vaultID, info.Auth.EDV)))
	if err != nil {
		return nil, fmt.Errorf("update document: %w", err)
	}

	return &DocumentMetadata{ID: id, URI: buildEDVURI(c.edvHost, edvVaultID, eID)}, nil
}

type vaultInfo struct {
	KID  string         `json:"kid"`
	Auth *Authorization `json:"auth"`
}

func (c *Client) saveVaultInfo(id string, info *vaultInfo) error {
	src, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return c.store.Put(fmt.Sprintf("info_%s", id), src)
}

func (c *Client) createIDAlias(id string) (string, error) {
	edvID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		return "", fmt.Errorf("generate EDV compatible id: %w", err)
	}

	err = c.store.Put(fmt.Sprintf("alias_%s", id), []byte(edvID))
	if err != nil {
		return "", fmt.Errorf("store put: %w", err)
	}

	return edvID, nil
}

func (c *Client) getIDAlias(id string) (string, error) {
	edvID, err := c.store.Get(fmt.Sprintf("alias_%s", id))
	if err != nil {
		return "", fmt.Errorf("store get: %w", err)
	}

	return string(edvID), nil
}

func (c *Client) getVaultInfo(id string) (*vaultInfo, error) {
	src, err := c.store.Get(fmt.Sprintf("info_%s", id))
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}

	var info *vaultInfo

	err = json.Unmarshal(src, &info)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return info, nil
}

func (c *Client) webKMS(controller string, auth *Location) *webkms.RemoteKMS {
	return webkms.New(
		c.buildMKSURL(auth.URI),
		c.httpClient,
		webkms.WithHeaders(c.kmsSign(controller, auth)),
	)
}

func (c *Client) buildMKSURL(uri string) string {
	if strings.HasPrefix(uri, "/") {
		return c.remoteKMSURL + uri
	}

	return uri
}

func (c *Client) webCrypto(controller string, auth *Location) *webcrypto.RemoteCrypto {
	return webcrypto.New(
		c.buildMKSURL(auth.URI),
		c.httpClient,
		webkms.WithHeaders(c.kmsSign(controller, auth)),
	)
}

func (c *Client) createDIDKey() (string, string, string, error) {
	sig, err := signature.NewCryptoSigner(c.crypto, c.kms, kms.ED25519)
	if err != nil {
		return "", "", "", fmt.Errorf("new crypto signer: %w", err)
	}

	cryptoSigner, ok := sig.(interface{ KID() string })
	if !ok {
		return "", "", "", errors.New("cannot retrieve the KID")
	}

	didKey, didURL := fingerprint.CreateDIDKey(sig.PublicKeyBytes())

	return didKey, didURL, cryptoSigner.KID(), nil
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

	didURL, err := toDidURL(controller)
	if err != nil {
		return nil, fmt.Errorf("to DidURL: %w", err)
	}

	err = hs.Sign(didURL, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign http request: %w", err)
	}

	return &req.Header, nil
}

func toDidURL(did string) (string, error) {
	pub, err := fingerprint.PubKeyFromDIDKey(did)
	if err != nil {
		return "", err
	}

	_, didURL := fingerprint.CreateDIDKey(pub)

	return didURL, nil
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

func uncompressZCAP(zcap string) (*zcapld.Capability, error) {
	src, err := base64.URLEncoding.DecodeString(zcap)
	if err != nil {
		return nil, err
	}

	zr, err := gzip.NewReader(bytes.NewBuffer(src))
	if err != nil {
		return nil, err
	}

	result, err := ioutil.ReadAll(zr)
	if err != nil {
		return nil, err
	}

	err = zr.Close()
	if err != nil {
		return nil, err
	}

	return zcapld.ParseCapability(result)
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

type signer struct {
	crypto crypto.Crypto
	kh     interface{}
}

func newSigner(cr crypto.Crypto, kh interface{}) *signer {
	return &signer{crypto: cr, kh: kh}
}

func (s *signer) Sign(data []byte) ([]byte, error) {
	return s.crypto.Sign(data, s.kh)
}
