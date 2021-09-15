/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/kid/resolver"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"

	vaultclient "github.com/trustbloc/edge-service/pkg/client/vault"
	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	"github.com/trustbloc/edge-service/pkg/restapi/vault"
	"github.com/trustbloc/edge-service/test/bdd/pkg/bddutil"
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
	crypto         ariescrypto.Crypto
	orbVDR         *orb.VDR
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

	t, err := orb.New(nil, orb.WithDomain("testnet.orb.local"),
		orb.WithTLSConfig(ctx.TLSConfig),
	)
	if err != nil {
		panic(err)
	}

	return &Steps{
		crypto:         cryptoService,
		kms:            keyManager,
		variableMapper: map[string]string{},
		authorizations: map[string]*vault.CreatedAuthorization{},
		orbVDR:         t,
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
	s.Step(`^Save a document with the following id "([^"]*)" with data "([^"]*)"$`, e.saveDocument)
	s.Step(`^Save a document without id and save the result ID as "([^"]*)"$`, e.saveDocumentWithoutID)
	s.Step(`^Check that a document with id "([^"]*)" is stored$`, e.getDocument)
	s.Step(`^Create a new "([^"]*)" authorization with duration "([^"]*)" and save the result as "([^"]*)"$`,
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
		return fmt.Errorf("failed to fetch doc: %w", err)
	}

	URIParts := strings.Split(docMeta.URI, "/")

	edvClient := edv.New("http://" + URIParts[2] + "/" + URIParts[3])

	eDoc, err := edvClient.ReadDocument(URIParts[4], URIParts[6], edv.WithRequestHeader(
		e.edvSign(authorization.RequestingParty, authorization.Tokens.EDV)),
	)
	if err != nil {
		return fmt.Errorf("edvClient failed to read document: %w", err)
	}

	store, err := mem.NewProvider().OpenStore("test")
	if err != nil {
		return fmt.Errorf("failed to open mem store: %w", err)
	}

	decrypter := ariesjose.NewJWEDecrypt(
		[]resolver.KIDResolver{&resolver.StoreResolver{Store: store}},
		webcrypto.New(
			e.kmsURI,
			e.client,
			webkms.WithHeaders(e.kmsSign(authorization.RequestingParty, authorization.Tokens.KMS)),
		),
		webkms.New(
			e.kmsURI,
			e.client,
			webkms.WithHeaders(e.kmsSign(authorization.RequestingParty, authorization.Tokens.KMS)),
		),
	)

	JWE, err := ariesjose.Deserialize(string(eDoc.JWE))
	if err != nil {
		return fmt.Errorf("failed to decrypt JWE: %w", err)
	}

	_, err = decrypter.Decrypt(JWE)

	return err
}

func (e *Steps) checkNotAvailable(docID, auth string) error {
	authorization, ok := e.authorizations[auth]
	if !ok {
		return errors.New("no authorization")
	}

	time.Sleep(time.Duration(authorization.Scope.Caveats[0].Duration+1) * time.Second) // nolint:durationcheck

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

func (e *Steps) createAuthorization(method, duration, name string) error {
	sec, err := strconv.Atoi(duration)
	if err != nil {
		return err
	}

	var requestingParty string
	if method == "key" {
		requestingParty, err = e.createDIDKey()
		if err != nil {
			return err
		}
	}

	if method == "orb" {
		requestingParty, err = e.createDIDORB()
		if err != nil {
			return err
		}
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

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, e.bddContext.VaultID, 10)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) saveDoc(docID, data string) (*vault.DocumentMetadata, error) {
	res, err := vaultclient.New(e.vaultURL, vaultclient.WithHTTPClient(e.client)).SaveDoc(e.vaultID, docID,
		map[string]interface{}{
			"contents": data,
		})
	if err != nil {
		return nil, err
	}

	if res.ID == "" || res.URI == "" {
		return nil, errors.New("result is empty")
	}

	return res, nil
}

func (e *Steps) saveDocumentWithoutID(name string) error {
	result, err := e.saveDoc("", "data")
	if err != nil {
		return err
	}

	e.variableMapper[name] = result.ID

	return nil
}

func (e *Steps) saveDocument(docID, data string) error {
	_, err := e.saveDoc(docID, data)

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
		Resolver: ariesvdr.New(
			ariesvdr.WithVDR(vdrkey.New()),
			ariesvdr.WithVDR(e.orbVDR),
		),
	})

	err := hs.Sign(controller, req)
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

	_, didURL := fingerprint.CreateDIDKey(sig.PublicKeyBytes())

	return didURL, nil
}

func (e *Steps) createDIDORB() (string, error) {
	didDoc, err := newDidDoc(e.kms)
	if err != nil {
		return "", err
	}

	recoverKey, err := newKey(e.kms)
	if err != nil {
		return "", err
	}

	updateKey, err := newKey(e.kms)
	if err != nil {
		return "", err
	}

	docResolution, err := e.orbVDR.Create(didDoc,
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoverKey),
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.AnchorOriginOpt, "https://testnet.orb.local"),
	)
	if err != nil {
		return "", err
	}

	_, err = bddutil.ResolveDID(e.bddContext.VDRI, docResolution.DIDDocument.ID, 10)
	if err != nil {
		return "", err
	}

	return docResolution.DIDDocument.CapabilityDelegation[0].VerificationMethod.ID, nil
}

func newDidDoc(k kms.KeyManager) (*did.Doc, error) {
	didDoc := &did.Doc{}

	publicKey, err := newKey(k)
	if err != nil {
		return nil, err
	}

	jwk, err := jwksupport.JWKFromKey(publicKey)
	if err != nil {
		return nil, err
	}

	vm, err := did.NewVerificationMethodFromJWK(uuid.New().String(), vccrypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, err
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))
	didDoc.CapabilityDelegation = append(didDoc.CapabilityDelegation,
		*did.NewReferencedVerification(vm, did.CapabilityDelegation))

	return didDoc, nil
}

func newKey(k kms.KeyManager) (crypto.PublicKey, error) {
	_, bits, err := k.CreateAndExportPubKeyBytes(kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to create key : %w", err)
	}

	return ed25519.PublicKey(bits), nil
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
