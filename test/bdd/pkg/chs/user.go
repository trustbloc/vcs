/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package chs

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	remotecrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/edvutils"
	models2 "github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"

	"github.com/trustbloc/edge-service/pkg/client/csh/client"
	"github.com/trustbloc/edge-service/pkg/client/csh/client/operations"
	"github.com/trustbloc/edge-service/pkg/client/csh/models"
	zcapld2 "github.com/trustbloc/edge-service/pkg/restapi/csh/operation/zcapld"
)

const requestTimeout = 5 * time.Second

func newUser(cshBaseURL, edvURL, hubkmsBaseURL string, tlsConfig *tls.Config) (*user, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	transport := httptransport.NewWithClient(
		cshBaseURL,
		client.DefaultBasePath,
		client.DefaultSchemes,
		httpClient,
	)

	user := &user{
		cshClient: client.New(transport, strfmt.Default),
	}

	err := user.initKeystore(hubkmsBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to init keystore: %w", err)
	}

	err = user.initConfidentialStorage(edvURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to init confidential storage vault: %w", err)
	}

	return user, nil
}

type user struct {
	localkms         kms.KeyManager
	webkms           kms.KeyManager
	localcrypto      crypto.Crypto
	remotecrypto     crypto.Crypto
	profile          *models.Profile
	controller       string
	signer           signature.Signer
	cshClient        *client.ConfidentialStorageHub
	keystoreURL      string
	keystoreRootZCAP string
	edvVaultID       string
	edvRootZCAP      string
	edvClient        *edv.Client
}

func (u *user) initKeystore(baseURL string, httpClient webkms.HTTPClient) error {
	var err error

	u.localkms, err = localkms.New(
		"local-lock://test/key-uri/",
		&mockKMSProvider{
			sp: mem.NewProvider(),
			sl: &noop.NoLock{},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to init local kms: %w", err)
	}

	u.localcrypto, err = tinkcrypto.New()
	if err != nil {
		return fmt.Errorf("failed to init local crypto: %w", err)
	}

	u.signer, err = signature.NewCryptoSigner(u.localcrypto, u.localkms, kms.ED25519Type)
	if err != nil {
		return fmt.Errorf("failed to create a new signer: %w", err)
	}

	u.controller = didKeyURL(u.signer.PublicKeyBytes())

	u.keystoreURL, u.keystoreRootZCAP, err = webkms.CreateKeyStore(httpClient, baseURL, u.controller, "")
	if err != nil {
		return fmt.Errorf("failed to create remote keystore: %w", err)
	}

	httpSigner := zcapld2.NewHTTPSigner(
		u.controller,
		u.keystoreRootZCAP,
		operation.CapabilityInvocationAction,
		&zcapld2.DIDSecrets{Secrets: map[string]httpsignatures.Secrets{
			"key": &zcapld.AriesDIDKeySecrets{},
		}},
		&zcapld2.DIDSignatureHashAlgorithms{
			KMS:       u.localkms,
			Crypto:    u.localcrypto,
			Resolvers: []zcapld2.DIDResolver{key.New()},
		},
	)

	u.webkms = webkms.New(
		u.keystoreURL,
		httpClient,
		webkms.WithHeaders(httpSigner),
	)

	u.remotecrypto = remotecrypto.New(
		u.keystoreURL,
		httpClient,
		webkms.WithHeaders(httpSigner),
	)

	return nil
}

func (u *user) initConfidentialStorage(baseURL string, httpClient edv.HTTPClient) error {
	var (
		err         error
		zcapBytes   []byte
		edvVaultURL string
	)

	tmp := edv.New(
		baseURL,
		edv.WithHTTPClient(httpClient),
	)

	edvVaultURL, zcapBytes, err = tmp.CreateDataVault(
		&models2.DataVaultConfiguration{
			Sequence:    0,
			Controller:  u.controller,
			ReferenceID: uuid.New().String(),
			KEK:         models2.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
			HMAC:        models2.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create Confidential Storage vault: %w", err)
	}

	u.edvRootZCAP, err = gzipThenBase64URL(zcapBytes)
	if err != nil {
		return fmt.Errorf("failed to compress edv zcap: %w", err)
	}

	u.edvClient = edv.New(
		baseURL,
		edv.WithHTTPClient(httpClient),
		edv.WithHeaders(zcapld2.NewHTTPSigner(
			u.controller,
			u.edvRootZCAP,
			func(r *http.Request) (string, error) {
				action := "write"

				if r.Method == http.MethodGet {
					action = "read"
				}

				return action, nil
			},
			&zcapld2.DIDSecrets{Secrets: map[string]httpsignatures.Secrets{
				"key": &zcapld.AriesDIDKeySecrets{},
			}},
			&zcapld2.DIDSignatureHashAlgorithms{
				KMS:       u.localkms,
				Crypto:    u.localcrypto,
				Resolvers: []zcapld2.DIDResolver{key.New()},
			},
		)),
	)

	u.edvVaultID = pathLeaf(edvVaultURL)

	return nil
}

func (u *user) requestNewProfile() error {
	response, err := u.cshClient.Operations.PostHubstoreProfiles(
		operations.NewPostHubstoreProfilesParams().
			WithTimeout(requestTimeout).
			WithRequest(&models.Profile{
				Controller: &u.controller,
			}),
	)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	u.profile = response.Payload

	return nil
}

func (u *user) saveInConfidentialStorage(msg string) (*docCoords, error) {
	docID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate an EDV-compatible document ID: %w", err)
	}

	vc, err := u.newVC(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new VC: %w", err)
	}

	vcRaw, err := json.Marshal(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vc: %w", err)
	}

	vcMap := make(map[string]interface{})

	err = json.Unmarshal(vcRaw, &vcMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vc: %w", err)
	}

	structuredDoc, err := json.Marshal(&models2.StructuredDocument{
		ID:      docID,
		Content: vcMap,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EDV structured document: %w", err)
	}

	jwe, err := encryptedJWE(structuredDoc, u.webkms, u.remotecrypto)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt msg as JWE: %w", err)
	}

	serialized, err := jwe.FullSerialize(json.Marshal)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JWE: %w", err)
	}

	encryptedDoc := &models2.EncryptedDocument{
		ID:       docID,
		Sequence: 0,
		JWE:      []byte(serialized),
	}

	docURI, err := u.edvClient.CreateDocument(u.edvVaultID, encryptedDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to save edv document: %w", err)
	}

	parts := strings.Split(docURI, "/")
	vaultID := parts[len(parts)-3]

	return &docCoords{
		vaultID: vaultID,
		docID:   docID,
		path:    "$.credentialSubject.testMessage",
	}, nil
}

func (u *user) newVC(msg string) (*verifiable.Credential, error) {
	vc := &verifiable.Credential{
		ID:      uuid.New().URN(),
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Issuer:  verifiable.Issuer{ID: u.controller},
		Subject: &verifiable.Subject{
			ID: uuid.New().URN(),
			CustomFields: map[string]interface{}{
				"testMessage": msg,
			},
		},
	}

	signer, err := signature.NewCryptoSigner(u.remotecrypto, u.webkms, kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new signer: %w", err)
	}

	err = vc.AddLinkedDataProof(
		&verifiable.LinkedDataProofContext{
			SignatureType:           ed25519signature2018.SignatureType,
			Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
			SignatureRepresentation: verifiable.SignatureJWS,
			Purpose:                 "assertionMethod",
			VerificationMethod:      didKeyURL(signer.PublicKeyBytes()),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add linked data proof to the vc: %w", err)
	}

	return vc, nil
}

// TODO docID should eventually be used once the EDV can handle zcaps for individual documents and not
//  the entire vaults.
func (u *user) authorizeRead(invoker, _ string) (string, string, error) { // nolint:funlen,gocyclo
	raw, err := base64URLDecodeThenGunzip(u.edvRootZCAP)
	if err != nil {
		return "", "", fmt.Errorf("failed to decompress edv zcap: %w", err)
	}

	rootEdvZCAP, err := zcapld.ParseCapability(raw)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse edv zcap: %w", err)
	}

	chain := make([]interface{}, 0)
	chain = append(chain, capabilityChain(rootEdvZCAP)...)
	chain = append(chain, rootEdvZCAP.ID)

	authorizedEDVZcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(u.signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: u.controller,
		},
		zcapld.WithInvoker(invoker),
		zcapld.WithAllowedActions("read"),
		zcapld.WithInvocationTarget(
			rootEdvZCAP.InvocationTarget.ID,
			rootEdvZCAP.InvocationTarget.Type,
		),
		zcapld.WithParent(rootEdvZCAP.ID),
		zcapld.WithCapabilityChain(chain...),
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to create authorized EDV capability: %w", err)
	}

	raw, err = json.Marshal(authorizedEDVZcap)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal authorized edv zcap: %w", err)
	}

	compressedEdvZCAP, err := gzipThenBase64URL(raw)
	if err != nil {
		return "", "", fmt.Errorf("failed to compress authorized edv zcap: %w", err)
	}

	raw, err = base64URLDecodeThenGunzip(u.keystoreRootZCAP)
	if err != nil {
		return "", "", fmt.Errorf("failed to decompress kms zcap: %w", err)
	}

	rootKmsZCAP, err := zcapld.ParseCapability(raw)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse KMS zcap: %w", err)
	}

	chain = make([]interface{}, 0)
	chain = append(chain, capabilityChain(rootKmsZCAP)...)
	chain = append(chain, rootKmsZCAP.ID)

	authorizedKMSZcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(u.signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: u.controller,
		},
		zcapld.WithInvoker(invoker),
		zcapld.WithAllowedActions("unwrap"),
		zcapld.WithInvocationTarget(
			rootKmsZCAP.InvocationTarget.ID,
			rootKmsZCAP.InvocationTarget.Type,
		),
		zcapld.WithParent(rootKmsZCAP.ID),
		zcapld.WithCapabilityChain(chain...),
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to create authorized KMS capability: %w", err)
	}

	raw, err = json.Marshal(authorizedKMSZcap)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal authorized kms zcap: %w", err)
	}

	compressedKMSZcap, err := gzipThenBase64URL(raw)
	if err != nil {
		return "", "", fmt.Errorf("failed to compress authorized kms zcap: %w", err)
	}

	return compressedEdvZCAP, compressedKMSZcap, nil
}

// nolint:interfacer // only support doc queries for now
func (u *user) createRef(docQuery *models.DocQuery) (string, error) {
	response, err := u.cshClient.Operations.PostHubstoreProfilesProfileIDQueries(
		operations.NewPostHubstoreProfilesProfileIDQueriesParams().
			WithTimeout(requestTimeout).
			WithProfileID(u.profile.ID).
			WithRequest(docQuery),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create ref: %w", err)
	}

	location, err := url.Parse(response.Location)
	if err != nil {
		return "", fmt.Errorf("failed to parse response location [%s]: %w", response.Location, err)
	}

	_, ref := filepath.Split(location.Path)

	return ref, nil
}

func (u *user) compare(queries ...models.Query) (bool, error) {
	op := &models.EqOp{}
	op.SetArgs(queries)

	request := &models.ComparisonRequest{}
	request.SetOp(op)

	response, err := u.cshClient.Operations.PostCompare(
		operations.NewPostCompareParams().
			WithTimeout(requestTimeout).
			WithRequest(request),
	)
	if err != nil {
		return false, fmt.Errorf("failed to execute comparison: %w", err)
	}

	return response.Payload.Result, nil
}

func (u *user) extract(queries ...models.Query) ([]interface{}, error) {
	response, err := u.cshClient.Operations.PostExtract(
		operations.NewPostExtractParams().
			WithTimeout(requestTimeout).
			WithRequest(queries),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to extract documents: %w", err)
	}

	return response.Payload, nil
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func encryptedJWE(msg []byte, km kms.KeyManager, c crypto.Crypto) (*jose.JSONWebEncryption, error) {
	_, rawPubKey, err := km.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
	if err != nil {
		return nil, fmt.Errorf("failed to create kek: %w", err)
	}

	recipientKey := &crypto.PublicKey{}

	err = json.Unmarshal(rawPubKey, recipientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal kek: %w", err)
	}

	jweEncrpt, err := jose.NewJWEEncrypt(
		jose.A256GCM,
		"",
		"",
		nil,
		[]*crypto.PublicKey{recipientKey},
		c,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init JWEEncrypter: %w", err)
	}

	jwe, err := jweEncrpt.Encrypt(msg)
	if err != nil {
		return nil, fmt.Errorf("jweencrypter failed to encrypt msg: %w", err)
	}

	return jwe, nil
}

func pathLeaf(p string) string {
	s := strings.Split(p, "/")
	return s[len(s)-1]
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
