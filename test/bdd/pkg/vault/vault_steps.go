/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"

	vaultclient "github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
	"github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const keystorePrimaryKeyURI = "local-lock://keystorekms"

// Steps is steps for vault tests.
type Steps struct {
	bddContext     *context.BDDContext
	client         *http.Client
	vaultID        string
	vaultURL       string
	variableMapper map[string]string
	authorizations map[string]*vault.CreatedAuthorization
	kms            kms.KeyManager
	kmsURI         string
	crypto         crypto.Crypto
}

// NewSteps returns new vault steps.
func NewSteps(ctx *context.BDDContext) *Steps {
	cryptoService, err := tinkcrypto.New()
	if err != nil {
		panic(err)
	}

	keyManager, err := localkms.New(keystorePrimaryKeyURI, &kmsProvider{
		storageProvider: mem.NewProvider(),
		secretLock:      &noop.NoLock{},
	})
	if err != nil {
		panic(err)
	}

	return &Steps{
		crypto:         cryptoService,
		kms:            keyManager,
		variableMapper: map[string]string{},
		authorizations: map[string]*vault.CreatedAuthorization{},
		bddContext:     ctx, client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: ctx.TLSConfig,
			},
		},
	}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Create a new vault using the vault server "([^"]*)"$`, e.createVault)
	s.Step(`^Save a document with the following id "([^"]*)"$`, e.saveDocument)
	s.Step(`^Save a document without id and save the result ID as "([^"]*)"$`, e.saveDocumentWithoutID)
	s.Step(`^Check that a document with id "([^"]*)" is stored$`, e.getDocument)
	s.Step(`^Create a new authorization with duration "([^"]*)" and save the result as "([^"]*)"$`,
		e.createAuthorization)
	s.Step(`^Check that a document with id "([^"]*)" is available for "([^"]*)"$`, e.checkAccessibility)
	s.Step(`^Check that a document with id "([^"]*)" is not available for "([^"]*)"$`, e.checkNotAvailable)
	s.Step(`^Check that an authorization "([^"]*)" was stored$`, e.checkAuthorization)
}

func (e *Steps) checkAccessibility(docID, auth string) error {
	authorization, ok := e.authorizations[auth]
	if !ok {
		return errors.New("no authorization")
	}

	docMeta, err := e.getDoc(docID)
	if err != nil {
		return err
	}

	URIParts := strings.Split(docMeta.URI, "/")

	edvClient := edv.New("http://" + URIParts[2] + "/" + URIParts[3])

	eDoc, err := edvClient.ReadDocument(URIParts[4], URIParts[6], edv.WithRequestHeader(
		e.edvSign(authorization.RequestingParty, authorization.Tokens.EDV)),
	)
	if err != nil {
		return err
	}

	store, err := mem.NewProvider().OpenStore("test")
	if err != nil {
		return err
	}

	decrypter := jose.NewJWEDecrypt(store, webcrypto.New(
		e.kmsURI,
		e.client,
		webkms.WithHeaders(e.kmsSign(authorization.RequestingParty, authorization.Tokens.KMS)),
	), webkms.New(
		e.kmsURI,
		e.client,
		webkms.WithHeaders(e.kmsSign(authorization.RequestingParty, authorization.Tokens.KMS)),
	))

	JWE, err := jose.Deserialize(string(eDoc.JWE))
	if err != nil {
		return err
	}

	_, err = decrypter.Decrypt(JWE)

	return err
}

func (e *Steps) checkNotAvailable(docID, auth string) error {
	authorization, ok := e.authorizations[auth]
	if !ok {
		return errors.New("no authorization")
	}

	time.Sleep(time.Duration(authorization.Scope.Caveats[0].Duration+1) * time.Second)

	docMeta, err := e.getDoc(docID)
	if err != nil {
		return err
	}

	URIParts := strings.Split(docMeta.URI, "/")

	edvClient := edv.New("http://" + URIParts[2] + "/" + URIParts[1])

	_, err = edvClient.ReadDocument(URIParts[4], URIParts[6], edv.WithRequestHeader(
		e.edvSign(authorization.RequestingParty, authorization.Tokens.EDV)),
	)

	if err == nil {
		return errors.New("expected an error, but got <nil>")
	}

	if strings.Contains(err.Error(), "caveat expiry: token expired") {
		return nil
	}

	return err
}

func (e *Steps) createAuthorization(duration, name string) error {
	sec, err := strconv.Atoi(duration)
	if err != nil {
		return err
	}

	requestingParty, err := e.createDIDKey()
	if err != nil {
		return err
	}

	result, err := vaultclient.New(e.vaultURL, vaultclient.WithHTTPClient(e.client)).CreateAuthorization(
		e.vaultID,
		requestingParty,
		&vault.AuthorizationsScope{
			Target:  e.vaultID,
			Actions: []string{"read"},
			Caveats: []vault.Caveat{{Type: zcapld.CaveatTypeExpiry, Duration: uint64(sec)}},
		},
	)
	if err != nil {
		return err
	}

	if result.ID == "" {
		return errors.New("id is empty")
	}

	e.authorizations[name] = result

	return nil
}

func (e *Steps) createVault(endpoint string) error {
	result, err := vaultclient.New(endpoint, vaultclient.WithHTTPClient(e.client)).CreateVault()
	if err != nil {
		return err
	}

	if result.ID == "" {
		return errors.New("id is empty")
	}

	e.vaultID = result.ID
	e.vaultURL = endpoint
	e.kmsURI = result.KMS.URI

	e.bddContext.VaultID = result.ID

	return nil
}

func (e *Steps) saveDoc(docID string) (*vault.DocumentMetadata, error) {
	res, err := vaultclient.New(e.vaultURL, vaultclient.WithHTTPClient(e.client)).SaveDoc(e.vaultID, docID, nil)
	if err != nil {
		return nil, err
	}

	if res.ID == "" || res.URI == "" {
		return nil, errors.New("result is empty")
	}

	return res, nil
}

func (e *Steps) saveDocumentWithoutID(name string) error {
	result, err := e.saveDoc("")
	if err != nil {
		return err
	}

	e.variableMapper[name] = result.ID

	return nil
}

func (e *Steps) saveDocument(docID string) error {
	_, err := e.saveDoc(docID)

	return err
}

func (e *Steps) getDocument(id string) error {
	docID, ok := e.variableMapper[id]
	if !ok {
		docID = id
	}

	_, err := e.getDoc(docID)

	return err
}

func (e *Steps) checkAuthorization(auth string) error {
	authorization, ok := e.authorizations[auth]
	if !ok {
		return errors.New("no authorization")
	}

	result, err := vaultclient.New(e.vaultURL, vaultclient.WithHTTPClient(e.client)).
		GetAuthorization(e.vaultID, authorization.ID)
	if err != nil {
		return err
	}

	if result.ID == "" || result.Tokens.KMS == "" || result.Tokens.EDV == "" {
		return errors.New("result is empty")
	}

	return nil
}

func (e *Steps) kmsSign(controller, authToken string) func(req *http.Request) (*http.Header, error) {
	return func(req *http.Request) (*http.Header, error) {
		action, err := operation.CapabilityInvocationAction(req)
		if err != nil {
			return nil, fmt.Errorf("capability invocation action: %w", err)
		}

		return e.sign(req, controller, action, authToken)
	}
}

func (e *Steps) getDoc(id string) (*vault.DocumentMetadata, error) {
	docID, ok := e.variableMapper[id]
	if !ok {
		docID = id
	}

	result, err := vaultclient.New(e.vaultURL, vaultclient.WithHTTPClient(e.client)).GetDocMetaData(e.vaultID, docID)
	if err != nil {
		return nil, err
	}

	if result.ID == "" || result.URI == "" {
		return nil, errors.New("result is empty")
	}

	return result, nil
}

func (e *Steps) edvSign(controller, authToken string) func(req *http.Request) (*http.Header, error) {
	return func(req *http.Request) (*http.Header, error) {
		action := "write"
		if req.Method == http.MethodGet {
			action = "read"
		}

		return e.sign(req, controller, action, authToken)
	}
}

func (e *Steps) sign(req *http.Request, controller, action, zcap string) (*http.Header, error) {
	req.Header.Set(
		zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`, zcap, action),
	)

	hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
	hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
		Crypto: e.crypto,
		KMS:    e.kms,
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

func (e *Steps) createDIDKey() (string, error) {
	sig, err := signature.NewCryptoSigner(e.crypto, e.kms, kms.ED25519)
	if err != nil {
		return "", fmt.Errorf("new crypto signer: %w", err)
	}

	didKey, _ := fingerprint.CreateDIDKey(sig.PublicKeyBytes())

	return didKey, nil
}

func toDidURL(did string) (string, error) {
	pub, err := fingerprint.PubKeyFromDIDKey(did)
	if err != nil {
		return "", err
	}

	_, didURL := fingerprint.CreateDIDKey(pub)

	return didURL, nil
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}
