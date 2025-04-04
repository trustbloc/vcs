/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import (
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/did/endpoint"
	"github.com/trustbloc/did-go/method/key"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

// nolint: gochecknoglobals
var signatureTypeToDidVerificationMethod = map[vcsverifiable.SignatureType]string{
	vcsverifiable.Ed25519Signature2020:        crypto.Ed25519VerificationKey2020,
	vcsverifiable.Ed25519Signature2018:        crypto.Ed25519VerificationKey2018,
	vcsverifiable.JSONWebSignature2020:        crypto.JSONWebKey2020,
	vcsverifiable.EcdsaSecp256k1Signature2019: crypto.EcdsaSecp256k1VerificationKey2019,
	vcsverifiable.BbsBlsSignature2020:         crypto.Bls12381G2Key2020,
	// JWT
	vcsverifiable.EdDSA:  crypto.JSONWebKey2020,
	vcsverifiable.ES256K: crypto.JSONWebKey2020,
	vcsverifiable.ES256:  crypto.JSONWebKey2020,
	vcsverifiable.ES384:  crypto.JSONWebKey2020,
	vcsverifiable.PS256:  crypto.JSONWebKey2020,
	vcsverifiable.RS256:  crypto.JSONWebKey2020,
}

// createResult contains created did, update and recovery keys.
type createResult struct {
	didID          string
	creator        string
	kmsKeyID       string
	updateKeyURL   string
	recoveryKeyURL string
}

// Creator service used to create public DID.
type Creator struct {
	config *creatorConfig
}

// KeysCreator create keys for DID creation process.
type KeysCreator interface {
	CreateJWKKey(keyType kmsapi.KeyType) (string, *jwk.JWK, error)
	CreateCryptoKey(keyType kmsapi.KeyType) (string, interface{}, error)
}

// creatorConfig configures PublicDID.
type creatorConfig struct {
	vdr vdrapi.Registry
}

// newCreator creates Creator.
func newCreator(config *creatorConfig) *Creator {
	return &Creator{
		config: config,
	}
}

// publicDID creates a new public DID given a key manager.
func (c *Creator) publicDID(method profileapi.Method, verificationMethodType vcsverifiable.SignatureType,
	keyType kmsapi.KeyType, km KeysCreator, didDomain, difDidOrigin string) (*createResult, error) {
	methods := map[profileapi.Method]func(verificationMethodType vcsverifiable.SignatureType, keyType kmsapi.KeyType,
		km KeysCreator, didDomain, difDidOrigin string) (*createResult, error){
		profileapi.KeyDIDMethod: c.keyDID,
		profileapi.OrbDIDMethod: c.createDID,
		profileapi.WebDIDMethod: c.webDID,
		"ion":                   c.ionDID,
		"jwk":                   c.jwkDID,
	}

	methodFn, supported := methods[method]
	if !supported {
		return nil, fmt.Errorf("unsupported did method: %s", method)
	}

	return methodFn(verificationMethodType, keyType, km, didDomain, difDidOrigin)
}

func (c *Creator) createDID(
	verificationMethodType vcsverifiable.SignatureType,
	keyType kmsapi.KeyType,
	km KeysCreator,
	_, _ string,
) (*createResult, error) { //nolint: unparam
	methods, err := newVerMethods(3, km, verificationMethodType, keyType) // nolint:mnd
	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create verification methods: %w", err)
	}

	authentication := methods[0]

	doc := &did.Doc{
		Authentication: []did.Verification{{
			VerificationMethod: *authentication,
			Relationship:       did.Authentication,
			Embedded:           true,
		}},
		AssertionMethod: []did.Verification{{
			VerificationMethod: *authentication,
			Relationship:       did.AssertionMethod,
			Embedded:           true,
		}},
	}

	keys := [2]interface{}{}
	keyURLs := [2]string{}
	types := [2]string{"update", "recovery"}

	for i := 0; i < 2; i++ {
		keyURLs[i], keys[i], err = km.CreateCryptoKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("did:orb: failed to create %s key: %w", types[i], err)
		}
	}

	updateKey, updateURL := keys[0], keyURLs[0]
	recoveryKey, recoveryURL := keys[1], keyURLs[1]

	didResolution, err := c.config.vdr.Create(
		"ion",
		doc,
		vdrapi.WithOption(longform.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(longform.RecoveryPublicKeyOpt, recoveryKey),
	)

	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create did: %w", err)
	}

	return &createResult{
		didID:          didResolution.DIDDocument.ID,
		creator:        didResolution.DIDDocument.ID + "#" + authentication.ID,
		kmsKeyID:       authentication.ID,
		updateKeyURL:   updateURL,
		recoveryKeyURL: recoveryURL,
	}, nil
}

func (c *Creator) keyDID(
	verificationMethodType vcsverifiable.SignatureType,
	keyType kmsapi.KeyType,
	km KeysCreator,
	_, _ string,
) (*createResult, error) { //nolint: unparam
	verMethod, err := newVerMethods(1, km, verificationMethodType, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create new ver method: %w", err)
	}

	didResolution, err := c.config.vdr.Create(
		key.DIDMethod,
		&did.Doc{
			VerificationMethod: []did.VerificationMethod{*verMethod[0]},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create did: %w", err)
	}

	return &createResult{
		didID:    didResolution.DIDDocument.ID,
		creator:  didResolution.DIDDocument.VerificationMethod[0].ID,
		kmsKeyID: verMethod[0].ID,
	}, nil
}

func (c *Creator) jwkDID(
	verificationMethodType vcsverifiable.SignatureType,
	keyType kmsapi.KeyType,
	km KeysCreator,
	_, _ string,
) (*createResult, error) { //nolint: unparam
	verMethod, err := newVerMethods(1, km, verificationMethodType, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create new ver method: %w", err)
	}

	didResolution, err := c.config.vdr.Create(
		key.DIDMethod,
		&did.Doc{
			VerificationMethod: []did.VerificationMethod{*verMethod[0]},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("did:jwk failed to create did: %w", err)
	}

	return &createResult{
		didID:    didResolution.DIDDocument.ID,
		creator:  didResolution.DIDDocument.VerificationMethod[0].ID,
		kmsKeyID: verMethod[0].ID,
	}, nil
}

func (c *Creator) webDID(verificationMethodType vcsverifiable.SignatureType, keyType kmsapi.KeyType,
	km KeysCreator, didDomain, difDidOrigin string) (*createResult, error) {
	r, err := c.createDID(verificationMethodType, keyType, km, didDomain, difDidOrigin)
	if err != nil {
		return nil, err
	}

	didWeb := strings.ReplaceAll(r.didID, "orb", "web:"+strings.ReplaceAll(didDomain, "https://", ""))
	didWeb = strings.ReplaceAll(didWeb, "uAAA", "scid")

	creator := strings.ReplaceAll(r.creator, r.didID, didWeb)

	return &createResult{
		didID:          didWeb,
		creator:        creator,
		kmsKeyID:       strings.Split(creator, "#")[1],
		updateKeyURL:   r.updateKeyURL,
		recoveryKeyURL: r.recoveryKeyURL,
	}, nil
}

type serviceEndpointData struct {
	Origins []string `json:"origins"`
}

func (c *Creator) ionDID(
	verificationMethodType vcsverifiable.SignatureType,
	keyType kmsapi.KeyType,
	km KeysCreator, _, difDidOrigin string,
) (*createResult, error) { //nolint:unparam
	verMethod, err := newVerMethods(1, km, verificationMethodType, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:ion failed to create new ver method: %w", err)
	}

	vm := verMethod[0]

	didDoc := &did.Doc{
		Authentication: []did.Verification{{
			VerificationMethod: *vm,
			Relationship:       did.Authentication,
			Embedded:           true,
		}},
		AssertionMethod: []did.Verification{{
			VerificationMethod: *vm,
			Relationship:       did.AssertionMethod,
			Embedded:           true,
		}},
	}

	if difDidOrigin != "" {
		didDoc.Service = []did.Service{{ID: "LinkedDomains", Type: "LinkedDomains",
			ServiceEndpoint: endpoint.NewDIDCoreEndpoint(&serviceEndpointData{Origins: []string{difDidOrigin + "/"}})}}
	}

	keys := [2]interface{}{}
	keyURLs := [2]string{}
	types := [2]string{"update", "recovery"}

	for i := 0; i < 2; i++ {
		keyURLs[i], keys[i], err = km.CreateCryptoKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("did:ion: failed to create %s key: %w", types[i], err)
		}
	}

	updateKey, updateURL := keys[0], keyURLs[0]
	recoveryKey, recoveryURL := keys[1], keyURLs[1]

	didResolution, err := c.config.vdr.Create(
		"ion",
		didDoc,
		vdrapi.WithOption(longform.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(longform.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(longform.VDRAcceptOpt, "long-form"),
	)
	if err != nil {
		return nil, fmt.Errorf("did:ion failed to create long form did: %w", err)
	}

	return &createResult{
		didID:          didResolution.DIDDocument.ID,
		creator:        didResolution.DIDDocument.ID + "#" + vm.ID,
		kmsKeyID:       vm.ID,
		updateKeyURL:   updateURL,
		recoveryKeyURL: recoveryURL,
	}, nil
}

func newVerMethods(count int, km KeysCreator, verMethodType vcsverifiable.SignatureType,
	keyType kmsapi.KeyType) ([]*did.VerificationMethod, error) {
	methods := make([]*did.VerificationMethod, count)

	for i := 0; i < count; i++ {
		keyID, j, err := km.CreateJWKKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("failed to create key: %w", err)
		}

		verificationMethod := signatureTypeToDidVerificationMethod[verMethodType]

		// TODO sidetree doesn't support VM controller: https://github.com/decentralized-identity/sidetree/issues/1010
		vm, err := did.NewVerificationMethodFromJWK(
			keyID,
			verificationMethod,
			"",
			j,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to create verification method: %w", err)
		}

		methods[i] = vm
	}

	return methods, nil
}
