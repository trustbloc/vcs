/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"
	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"

	"github.com/trustbloc/edge-service/pkg/client/uniregistrar"
	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	recoveryKey = "recovery-key"
	updateKey   = "update-key"
)

// nolint: gochecknoglobals
var signatureKeyTypeMap = map[string]string{
	crypto.Ed25519Signature2018: crypto.Ed25519VerificationKey2018,
	crypto.JSONWebSignature2020: crypto.JwsVerificationKey2020,
}

// CommonDID common did operation
type CommonDID struct {
	uniRegistrarClient uniRegistrarClient
	trustBlocDIDClient didBlocClient
	keyManager         keyManager
	vdr                vdrapi.Registry
	domain             string
}

// Config defines configuration for vcs operations
type Config struct {
	KeyManager keyManager
	VDRI       vdrapi.Registry
	Domain     string
	TLSConfig  *tls.Config
}

type uniRegistrarClient interface {
	CreateDID(driverURL string, opts ...uniregistrar.CreateDIDOption) (string, []didmethodoperation.Key, error)
}

type didBlocClient interface {
	CreateDID(domain string, opts ...didclient.CreateDIDOption) (*ariesdid.Doc, error)
}

type keyManager interface {
	kms.KeyManager
}

// New return new instance of common DID
func New(config *Config) *CommonDID {
	return &CommonDID{uniRegistrarClient: uniregistrar.New(uniregistrar.WithTLSConfig(config.TLSConfig)),
		trustBlocDIDClient: didclient.New(didclient.WithTLSConfig(config.TLSConfig)),
		keyManager:         config.KeyManager,
		domain:             config.Domain,
		vdr:                config.VDRI,
	}
}

// CreateDID create did
func (o *CommonDID) CreateDID(keyType, signatureType, did, privateKey, keyID, purpose string,
	registrar model.UNIRegistrar) (string, string, error) {
	var didID string

	var publicKeyID string

	switch {
	case registrar.DriverURL != "":
		var err error
		didID, publicKeyID, err = o.createDIDUniRegistrar(keyType, signatureType, purpose, registrar)

		if err != nil {
			return "", "", err
		}

	case did == "":
		var err error
		didID, publicKeyID, err = o.createDID(keyType, signatureType)

		if err != nil {
			return "", "", err
		}

	case did != "":
		didDoc, err := o.vdr.Resolve(did)
		if err != nil {
			return "", "", fmt.Errorf("failed to resolve did: %v", err)
		}

		didID = didDoc.ID

		if privateKey != "" {
			if err := o.importKey(keyID, kms.ED25519Type, base58.Decode(privateKey)); err != nil {
				return "", "", err
			}
		}

		publicKeyID = keyID
	}

	didID, publicKeyID = o.replaceCanonicalDIDWithDomainDID(didID, publicKeyID)

	return didID, publicKeyID, nil
}

func (o *CommonDID) replaceCanonicalDIDWithDomainDID(didID, publicKeyID string) (string, string) {
	if strings.HasPrefix(didID, "did:trustbloc") {
		split := strings.Split(didID, ":")
		if len(split) == 4 {
			domainDIDID := fmt.Sprintf("%s:%s:%s:%s", split[0], split[1], o.domain, split[3])

			return domainDIDID, strings.ReplaceAll(publicKeyID, didID, domainDIDID)
		}
	}

	return didID, publicKeyID
}

// nolint: gocyclo,funlen
func (o *CommonDID) createDIDUniRegistrar(keyType, signatureType, purpose string,
	registrar model.UNIRegistrar) (string, string, error) {
	var opts []uniregistrar.CreateDIDOption

	publicKeys, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did public key: %v", err)
	}

	_, recoveryPubKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return "", "", err
	}

	_, updatePubKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return "", "", err
	}

	for _, v := range publicKeys {
		opts = append(opts, uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			ID: v.ID, Type: v.Type,
			Value:    base64.StdEncoding.EncodeToString(v.Value),
			KeyType:  v.KeyType,
			Encoding: v.Encoding, Purpose: v.Purpose}))
	}

	opts = append(opts,
		uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			ID: recoveryKey, Type: didclient.JWSVerificationKey2020,
			Value:    base64.StdEncoding.EncodeToString(recoveryPubKey),
			Encoding: didclient.PublicKeyEncodingJwk, Recovery: true}),
		uniregistrar.WithPublicKey(&didmethodoperation.PublicKey{
			ID: updateKey, Type: didclient.JWSVerificationKey2020,
			Value:    base64.StdEncoding.EncodeToString(updatePubKey),
			Encoding: didclient.PublicKeyEncodingJwk, Update: true}),
		uniregistrar.WithOptions(registrar.Options))

	identifier, keys, err := o.uniRegistrarClient.CreateDID(registrar.DriverURL, opts...)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did doc from uni-registrar: %v", err)
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
			for _, p := range v.Purpose {
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

func (o *CommonDID) createDID(keyType, signatureType string) (string, string, error) {
	var opts []didclient.CreateDIDOption

	publicKeys, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did public key: %v", err)
	}

	_, recoveryPubKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return "", "", err
	}

	_, updatePubKey, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return "", "", err
	}

	for _, v := range publicKeys {
		opts = append(opts, didclient.WithPublicKey(v))
	}

	opts = append(opts,
		didclient.WithPublicKey(&didclient.PublicKey{ID: recoveryKey,
			Type: didclient.JWSVerificationKey2020, Value: recoveryPubKey,
			Encoding: didclient.PublicKeyEncodingJwk, Recovery: true}),
		didclient.WithPublicKey(&didclient.PublicKey{ID: updateKey,
			Type: didclient.JWSVerificationKey2020, Value: updatePubKey,
			Encoding: didclient.PublicKeyEncodingJwk, Update: true}))

	didDoc, err := o.trustBlocDIDClient.CreateDID(o.domain, opts...)
	if err != nil {
		return "", "", fmt.Errorf("failed to create did doc: %v", err)
	}

	return didDoc.ID, didDoc.ID + "#" + selectedKeyID, nil
}

func (o *CommonDID) createPublicKeys(keyType, signatureType string) ([]*didclient.PublicKey, string, error) {
	var publicKeys []*didclient.PublicKey

	// Add Ed25519VerificationKey2018 Ed25519KeyType
	key1ID, pubKeyBytes, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return nil, "", err
	}

	publicKeys = append(publicKeys, &didclient.PublicKey{ID: key1ID, Type: didclient.Ed25519VerificationKey2018,
		Value: pubKeyBytes, Encoding: didclient.PublicKeyEncodingJwk,
		KeyType: didclient.Ed25519KeyType,
		Purpose: []string{didclient.KeyPurposeGeneral, didclient.KeyPurposeAssertion, didclient.KeyPurposeAuth}})

	// Add JWSVerificationKey2020 Ed25519KeyType
	key2ID, pubKeyBytes, err := o.createKey(kms.ED25519Type)
	if err != nil {
		return nil, "", err
	}

	publicKeys = append(publicKeys, &didclient.PublicKey{ID: key2ID, Type: didclient.JWSVerificationKey2020,
		Value: pubKeyBytes, Encoding: didclient.PublicKeyEncodingJwk,
		KeyType: didclient.Ed25519KeyType,
		Purpose: []string{didclient.KeyPurposeGeneral, didclient.KeyPurposeAssertion, didclient.KeyPurposeAuth}})

	// Add JWSVerificationKey2020  ECKeyType
	key3ID, pubKeyBytes, err := o.createKey(kms.ECDSAP256IEEEP1363)
	if err != nil {
		return nil, "", err
	}

	publicKeys = append(publicKeys, &didclient.PublicKey{ID: key3ID, Type: didclient.JWSVerificationKey2020,
		Value: pubKeyBytes, Encoding: didclient.PublicKeyEncodingJwk, KeyType: didclient.P256KeyType,
		Purpose: []string{didclient.KeyPurposeGeneral, didclient.KeyPurposeAssertion, didclient.KeyPurposeAuth}})

	if keyType == crypto.Ed25519KeyType &&
		didclient.Ed25519VerificationKey2018 == signatureKeyTypeMap[signatureType] {
		return publicKeys, key1ID, nil
	}

	if keyType == crypto.Ed25519KeyType &&
		didclient.JWSVerificationKey2020 == signatureKeyTypeMap[signatureType] {
		return publicKeys, key2ID, nil
	}

	if keyType == crypto.P256KeyType &&
		didclient.JWSVerificationKey2020 == signatureKeyTypeMap[signatureType] {
		return publicKeys, key3ID, nil
	}

	return nil, "",
		fmt.Errorf("no key found to match key type:%s and signature type:%s", keyType, signatureType)
}

func (o *CommonDID) createKey(keyType kms.KeyType) (string, []byte, error) {
	keyID, _, err := o.keyManager.Create(keyType)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, err := o.keyManager.ExportPubKeyBytes(keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, pubKeyBytes, nil
}

func (o *CommonDID) importKey(keyID string, keyType kms.KeyType, privateKeyBytes []byte) error {
	split := strings.Split(keyID, "#")

	var privKey interface{}

	switch keyType {
	case kms.ED25519Type:
		privKey = ed25519.PrivateKey(privateKeyBytes)
	default:
		return fmt.Errorf("import key type not supported %s", keyType)
	}

	_, _, err := o.keyManager.ImportPrivateKey(privKey,
		keyType, kms.WithKeyID(split[1]))
	if err != nil {
		return fmt.Errorf("failed to import private key: %v", err)
	}

	return nil
}
