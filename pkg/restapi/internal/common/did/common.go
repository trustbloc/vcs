/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"

	"github.com/trustbloc/edge-service/pkg/client/uniregistrar"
	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const splitDidIDLength = 4

// nolint: gochecknoglobals
var signatureKeyTypeMap = map[string]string{
	crypto.Ed25519Signature2018: crypto.Ed25519VerificationKey2018,
	crypto.JSONWebSignature2020: crypto.JSONWebKey2020,
}

// CommonDID common did operation
type CommonDID struct {
	uniRegistrarClient uniRegistrarClient
	keyManager         keyManager
	vdr                vdrapi.Registry
	domain             string
	createKey          func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error)
	didAnchorOrigin    string
}

// Config defines configuration for vcs operations
type Config struct {
	KeyManager      keyManager
	VDRI            vdrapi.Registry
	Domain          string
	TLSConfig       *tls.Config
	DIDAnchorOrigin string
}

type uniRegistrarClient interface {
	CreateDID(driverURL string, opts ...uniregistrar.CreateDIDOption) (string, []didmethodoperation.Key, error)
}

type keyManager interface {
	kms.KeyManager
}

// New return new instance of common DID
func New(config *Config) *CommonDID {
	return &CommonDID{uniRegistrarClient: uniregistrar.New(uniregistrar.WithTLSConfig(config.TLSConfig)),
		keyManager:      config.KeyManager,
		domain:          config.Domain,
		vdr:             config.VDRI,
		createKey:       createKey,
		didAnchorOrigin: config.DIDAnchorOrigin,
	}
}

// CreateDID create did
func (o *CommonDID) CreateDID(keyType, signatureType, didID, privateKey, keyID, purpose string,
	registrar model.UNIRegistrar) (string, string, error) {
	var createdDIDID string

	var publicKeyID string

	switch {
	case registrar.DriverURL != "":
		var err error
		createdDIDID, publicKeyID, err = o.createDIDUniRegistrar(keyType, signatureType, purpose, registrar)

		if err != nil {
			return "", "", err
		}

	case didID == "":
		var err error
		createdDIDID, publicKeyID, err = o.createDID(keyType, signatureType)

		if err != nil {
			return "", "", err
		}

	case didID != "":
		docResolution, err := o.vdr.Resolve(didID)
		if err != nil {
			return "", "", fmt.Errorf("failed to resolve did: %w", err)
		}

		createdDIDID = docResolution.DIDDocument.ID

		if privateKey != "" {
			kmsKeyType := kms.ED25519Type

			// TODO temporary fix, should be dynamic to support all key types
			if keyType == kms.BLS12381G2 {
				kmsKeyType = kms.BLS12381G2Type
			}

			if err := o.importKey(keyID, kmsKeyType, base58.Decode(privateKey)); err != nil {
				return "", "", err
			}
		}

		publicKeyID = keyID
	}

	createdDIDID, publicKeyID = o.replaceCanonicalDIDWithDomainDID(createdDIDID, publicKeyID)

	return createdDIDID, publicKeyID, nil
}

func (o *CommonDID) replaceCanonicalDIDWithDomainDID(didID, publicKeyID string) (string, string) {
	if strings.HasPrefix(didID, "did:trustbloc") {
		split := strings.Split(didID, ":")
		if len(split) == splitDidIDLength {
			domainDIDID := fmt.Sprintf("%s:%s:%s:%s", split[0], split[1], o.domain, split[3])

			return domainDIDID, strings.ReplaceAll(publicKeyID, didID, domainDIDID)
		}
	}

	return didID, publicKeyID
}

//nolint:gocyclo
func (o *CommonDID) createDIDUniRegistrar(keyType, signatureType, purpose string,
	registrar model.UNIRegistrar) (string, string, error) {
	_, pks, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did public key: %w", err)
	}

	_, recoveryPubKey, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return "", "", err
	}

	_, updatePubKey, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return "", "", err
	}

	opts := o.createCreateDIDOptions(pks, recoveryPubKey, updatePubKey, registrar)

	identifier, keys, err := o.uniRegistrarClient.CreateDID(registrar.DriverURL, opts...)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did doc from uni-registrar: %w", err)
	}

	// TODO https://github.com/trustbloc/edge-service/issues/415 remove check when vendors supporting addKeys feature
	if strings.Contains(identifier, "did:trustbloc") {
		for _, v := range keys {
			if strings.Contains(v.ID, "#"+selectedKeyID) {
				return identifier, v.ID, nil
			}
		}

		return "", "", fmt.Errorf("selected key not found %s", selectedKeyID)
	}

	if strings.Contains(identifier, "did:v1") {
		for _, v := range keys {
			for _, p := range v.Purposes {
				if purpose == p {
					err = o.importKey(v.ID, kms.ED25519Type, base58.Decode(v.PrivateKeyBase58))
					if err != nil {
						return "", "", err
					}

					return identifier, v.ID, nil
				}
			}
		}

		return "", "", fmt.Errorf("did:v1 - not able to find key with purpose %s", purpose)
	}

	// vendors not supporting addKeys feature.
	// return first key public and private
	// TODO https://github.com/trustbloc/edge-service/issues/415 remove when vendors supporting addKeys feature
	err = o.importKey(keys[0].ID, kms.ED25519Type, base58.Decode(keys[0].PrivateKeyBase58))
	if err != nil {
		return "", "", err
	}

	return identifier, keys[0].ID, nil
}

func (o *CommonDID) createCreateDIDOptions(pks []*didmethodoperation.PublicKey, recoveryPubKey []byte,
	updatePubKey []byte, registrar model.UNIRegistrar) []uniregistrar.CreateDIDOption {
	var opts []uniregistrar.CreateDIDOption

	for _, v := range pks {
		opts = append(opts, uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			ID: v.ID, Type: v.Type,
			Value:   v.Value,
			KeyType: v.KeyType, Purposes: v.Purposes}))
	}

	opts = append(opts,
		uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			KeyType: crypto.Ed25519KeyType, Value: base64.StdEncoding.EncodeToString(recoveryPubKey),
			Recovery: true}),
		uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			KeyType: crypto.Ed25519KeyType, Value: base64.StdEncoding.EncodeToString(updatePubKey),
			Update: true}),
		uniregistrar.WithOptions(registrar.Options))

	return opts
}

func (o *CommonDID) createDID(keyType, signatureType string) (string, string, error) {
	var opts []vdrapi.DIDMethodOption

	didDoc, _, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did public key: %w", err)
	}

	_, recoveryPubKey, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return "", "", err
	}

	_, updatePubKey, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return "", "", err
	}

	opts = append(opts,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, ed25519.PublicKey(recoveryPubKey)),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, ed25519.PublicKey(updatePubKey)),
		vdrapi.WithOption(orb.AnchorOriginOpt, o.didAnchorOrigin))

	docResolution, err := o.vdr.Create(orb.DIDMethod, didDoc, opts...)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did doc: %w", err)
	}

	docID := docResolution.DIDDocument.ID

	return docID, docID + "#" + selectedKeyID, nil
}

// nolint:funlen,gocyclo
func (o *CommonDID) createPublicKeys(keyType, signatureType string) (*did.Doc,
	[]*didmethodoperation.PublicKey, string, error) {
	didDoc := &did.Doc{}
	pks := make([]*didmethodoperation.PublicKey, 0)

	// Add key1
	key1ID, pubKeyBytes, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return nil, nil, "", err
	}

	jwk, err := jose.JWKFromKey(ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return nil, nil, "", err
	}

	vm, err := did.NewVerificationMethodFromJWK(key1ID, doc.Ed25519VerificationKey2018, "", jwk)
	if err != nil {
		return nil, nil, "", err
	}

	pks = append(pks, &didmethodoperation.PublicKey{ID: vm.ID, Type: vm.Type,
		KeyType: crypto.Ed25519KeyType, Value: base64.StdEncoding.EncodeToString(vm.Value),
		Purposes: []string{
			doc.KeyPurposeAssertionMethod,
			doc.KeyPurposeAuthentication,
		}})

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	// Add key2
	key2ID, pubKeyBytes, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return nil, nil, "", err
	}

	jwk, err = jose.JWKFromKey(ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return nil, nil, "", err
	}

	vm, err = did.NewVerificationMethodFromJWK(key2ID, crypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, nil, "", err
	}

	pks = append(pks, &didmethodoperation.PublicKey{ID: vm.ID, Type: vm.Type,
		KeyType: crypto.Ed25519KeyType, Value: base64.StdEncoding.EncodeToString(vm.Value),
		Purposes: []string{
			doc.KeyPurposeAssertionMethod,
			doc.KeyPurposeAuthentication,
		}})

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	// Add key3
	key3ID, pubKeyBytes, err := o.createKey(kms.ECDSAP256IEEEP1363, o.keyManager)
	if err != nil {
		return nil, nil, "", err
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)

	jwk, err = jose.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()})
	if err != nil {
		return nil, nil, "", err
	}

	vm, err = did.NewVerificationMethodFromJWK(key3ID, crypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, nil, "", err
	}

	pks = append(pks, &didmethodoperation.PublicKey{ID: vm.ID, Type: vm.Type,
		KeyType: crypto.P256KeyType, Value: base64.StdEncoding.EncodeToString(vm.Value),
		Purposes: []string{
			doc.KeyPurposeAssertionMethod,
			doc.KeyPurposeAuthentication,
		}})

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	if keyType == crypto.Ed25519KeyType &&
		doc.Ed25519VerificationKey2018 == signatureKeyTypeMap[signatureType] {
		return didDoc, pks, key1ID, nil
	}

	if keyType == crypto.Ed25519KeyType &&
		crypto.JSONWebKey2020 == signatureKeyTypeMap[signatureType] {
		return didDoc, pks, key2ID, nil
	}

	if keyType == crypto.P256KeyType &&
		crypto.JSONWebKey2020 == signatureKeyTypeMap[signatureType] {
		return didDoc, pks, key3ID, nil
	}

	return nil, nil, "",
		fmt.Errorf("no key found to match key type:%s and signature type:%s", keyType, signatureType)
}

func createKey(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
	keyID, _, err := keyManager.Create(keyType)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, err := keyManager.ExportPubKeyBytes(keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, pubKeyBytes, nil
}

func (o *CommonDID) importKey(keyID string, keyType kms.KeyType, privateKeyBytes []byte) error {
	split := strings.Split(keyID, "#")

	var privKey interface{}

	var err error

	switch keyType { //nolint:exhaustive
	case kms.ED25519Type:
		privKey = ed25519.PrivateKey(privateKeyBytes)
	case kms.BLS12381G2Type:
		privKey, err = bbs12381g2pub.UnmarshalPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to unmarshal private key: %w", err)
		}
	default:
		return fmt.Errorf("import key type not supported %s", keyType)
	}

	_, _, err = o.keyManager.ImportPrivateKey(privKey,
		keyType, kms.WithKeyID(split[1]))
	if err != nil {
		return fmt.Errorf("failed to import private key: %w", err)
	}

	return nil
}
