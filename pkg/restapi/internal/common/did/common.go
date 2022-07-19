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
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
)

const splitDidIDLength = 4

// nolint: gochecknoglobals
var signatureKeyTypeMap = map[string]string{
	crypto.Ed25519Signature2018: crypto.Ed25519VerificationKey2018,
	crypto.JSONWebSignature2020: crypto.JSONWebKey2020,
}

// CommonDID common did operation
type CommonDID struct {
	keyManager      keyManager
	vdr             vdrapi.Registry
	domain          string
	createKey       func(keyType kms.KeyType, keyManager keyManager) (string, []byte, error)
	didAnchorOrigin string
}

// Config defines configuration for vcs operations
type Config struct {
	KeyManager      keyManager
	VDRI            vdrapi.Registry
	Domain          string
	TLSConfig       *tls.Config
	DIDAnchorOrigin string
}

type keyManager interface {
	kms.KeyManager
}

// New return new instance of common DID
func New(config *Config) *CommonDID {
	return &CommonDID{
		keyManager:      config.KeyManager,
		domain:          config.Domain,
		vdr:             config.VDRI,
		createKey:       createKey,
		didAnchorOrigin: config.DIDAnchorOrigin,
	}
}

// CreateDID create did
func (o *CommonDID) CreateDID(keyType, signatureType, didID, privateKey, keyID string) (string, string, error) {
	var createdDIDID string

	var publicKeyID string

	switch {
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

func (o *CommonDID) createDID(keyType, signatureType string) (string, string, error) {
	var opts []vdrapi.DIDMethodOption

	didDoc, selectedKeyID, err := o.createPublicKeys(keyType, signatureType)
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
func (o *CommonDID) createPublicKeys(keyType, signatureType string) (*did.Doc, string, error) {
	didDoc := &did.Doc{}

	// Add key1
	key1ID, pubKeyBytes, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return nil, "", err
	}

	jwk, err := jwksupport.JWKFromKey(ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return nil, "", err
	}

	vm, err := did.NewVerificationMethodFromJWK(key1ID, doc.Ed25519VerificationKey2018, "", jwk)
	if err != nil {
		return nil, "", err
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	// Add key2
	key2ID, pubKeyBytes, err := o.createKey(kms.ED25519Type, o.keyManager)
	if err != nil {
		return nil, "", err
	}

	jwk, err = jwksupport.JWKFromKey(ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return nil, "", err
	}

	vm, err = did.NewVerificationMethodFromJWK(key2ID, crypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, "", err
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	// Add key3
	key3ID, pubKeyBytes, err := o.createKey(kms.ECDSAP256IEEEP1363, o.keyManager)
	if err != nil {
		return nil, "", err
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)

	jwk, err = jwksupport.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()})
	if err != nil {
		return nil, "", err
	}

	vm, err = did.NewVerificationMethodFromJWK(key3ID, crypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, "", err
	}

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.AssertionMethod = append(didDoc.AssertionMethod, *did.NewReferencedVerification(vm, did.AssertionMethod))

	if keyType == crypto.Ed25519KeyType &&
		doc.Ed25519VerificationKey2018 == signatureKeyTypeMap[signatureType] {
		return didDoc, key1ID, nil
	}

	if keyType == crypto.Ed25519KeyType &&
		crypto.JSONWebKey2020 == signatureKeyTypeMap[signatureType] {
		return didDoc, key2ID, nil
	}

	if keyType == crypto.P256KeyType &&
		crypto.JSONWebKey2020 == signatureKeyTypeMap[signatureType] {
		return didDoc, key3ID, nil
	}

	return nil, "",
		fmt.Errorf("no key found to match key type:%s and signature type:%s", keyType, signatureType)
}

func createKey(keyType kms.KeyType, keyManager keyManager) (string, []byte, error) {
	keyID, _, err := keyManager.Create(keyType)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, _, err := keyManager.ExportPubKeyBytes(keyID)
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
