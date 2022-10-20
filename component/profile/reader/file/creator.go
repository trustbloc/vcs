/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"

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
	vcsverifiable.BbsBlsSignature2020:         crypto.Bls12381G1Key2020,
	// JWT
	vcsverifiable.EdDSA:  crypto.JSONWebKey2020,
	vcsverifiable.ES256K: crypto.JSONWebKey2020,
	vcsverifiable.ES256:  crypto.JSONWebKey2020,
	vcsverifiable.ES384:  crypto.JSONWebKey2020,
	vcsverifiable.PS256:  crypto.JSONWebKey2020,
}

type uniRegistrarRequest struct {
	DIDDocument *json.RawMessage `json:"didDocument,omitempty"`
}

type uniRegistrarResponse struct {
	DIDDocumentMetadata didDocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

type didDocumentMetadata struct {
	LongFormDid string `json:"longFormDid,omitempty"`
}

// createResult contains created did, update and recovery keys.
type createResult struct {
	didID          string
	creator        string
	updateKeyURL   string
	recoveryKeyURL string
}

// Creator service used to create public DID.
type Creator struct {
	config *creatorConfig
}

// KeysCreator create keys for DID creation process.
type KeysCreator interface {
	CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error)
	CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error)
}

// creatorConfig configures PublicDID.
type creatorConfig struct {
	vdr vdr.Registry
}

// newCreator creates Creator.
func newCreator(config *creatorConfig) *Creator {
	return &Creator{
		config: config,
	}
}

// publicDID creates a new public DID given a key manager.
func (c *Creator) publicDID(method profileapi.Method, verificationMethodType vcsverifiable.SignatureType,
	keyType kms.KeyType, km KeysCreator, didDomain, difDidOrigin string) (*createResult, error) {
	methods := map[profileapi.Method]func(verificationMethodType vcsverifiable.SignatureType, keyType kms.KeyType,
		km KeysCreator, didDomain, difDidOrigin string) (*createResult, error){
		profileapi.KeyDIDMethod: c.keyDID,
		profileapi.OrbDIDMethod: c.createDID,
		profileapi.WebDIDMethod: c.webDID,
		"ion":                   c.ionDID,
	}

	methodFn, supported := methods[method]
	if !supported {
		return nil, fmt.Errorf("unsupported did method: %s", method)
	}

	return methodFn(verificationMethodType, keyType, km, didDomain, difDidOrigin)
}

func (c *Creator) createDID(verificationMethodType vcsverifiable.SignatureType, keyType kms.KeyType,
	km KeysCreator, didDomain, difDidOrigin string) (*createResult, error) { //nolint: unparam
	methods, err := newVerMethods(3, km, verificationMethodType, keyType) // nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create verification methods: %w", err)
	}

	authentication := methods[0]
	assertion := methods[0]
	capabilityDelegation := methods[1]
	capabilityInvocation := methods[2]

	doc := &did.Doc{
		Authentication: []did.Verification{{
			VerificationMethod: *authentication,
			Relationship:       did.Authentication,
			Embedded:           true,
		}},
		AssertionMethod: []did.Verification{{
			VerificationMethod: *assertion,
			Relationship:       did.AssertionMethod,
			Embedded:           true,
		}},
		CapabilityDelegation: []did.Verification{{
			VerificationMethod: *capabilityDelegation,
			Relationship:       did.CapabilityDelegation,
			Embedded:           true,
		}},
		CapabilityInvocation: []did.Verification{{
			VerificationMethod: *capabilityInvocation,
			Relationship:       did.CapabilityInvocation,
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
		orb.DIDMethod,
		doc,
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
	)

	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create did: %w", err)
	}

	return &createResult{
		didID:          didResolution.DIDDocument.ID,
		creator:        didResolution.DIDDocument.ID + "#" + assertion.ID,
		updateKeyURL:   updateURL,
		recoveryKeyURL: recoveryURL,
	}, nil
}

func (c *Creator) keyDID(verificationMethodType vcsverifiable.SignatureType, keyType kms.KeyType,
	km KeysCreator, didDomain, difDidOrigin string) (*createResult, error) { //nolint: unparam
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
		didID:   didResolution.DIDDocument.ID,
		creator: didResolution.DIDDocument.ID + "#" + verMethod[0].ID,
	}, nil
}

func (c *Creator) webDID(verificationMethodType vcsverifiable.SignatureType, keyType kms.KeyType,
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
		updateKeyURL:   r.updateKeyURL,
		recoveryKeyURL: r.recoveryKeyURL,
	}, nil
}

func (c *Creator) ionDID(verificationMethodType vcsverifiable.SignatureType, keyType kms.KeyType,
	km KeysCreator, didDomain, difDidOrigin string) (*createResult, error) {
	verMethod, err := newVerMethods(1, km, verificationMethodType, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:ion failed to create new ver method: %w", err)
	}

	vm := verMethod[0]
	vm.ID = "#" + vm.ID

	didDoc := &did.Doc{
		VerificationMethod: []did.VerificationMethod{*vm},
		AssertionMethod:    []did.Verification{{VerificationMethod: did.VerificationMethod{ID: vm.ID}}},
		Authentication:     []did.Verification{{VerificationMethod: did.VerificationMethod{ID: vm.ID}}},
	}

	if difDidOrigin != "" {
		didDoc.Service = []did.Service{{ID: "LinkedDomains", Type: "LinkedDomains",
			ServiceEndpoint: model.NewDIDCommV1Endpoint(difDidOrigin + "/")}}
	}

	b, err := didDoc.JSONBytes()
	if err != nil {
		return nil, err
	}

	a := json.RawMessage(b)

	req, err := json.Marshal(uniRegistrarRequest{DIDDocument: &a})

	// TODO https://github.com/hyperledger/aries-framework-go-ext/issues/288
	resp, err := http.DefaultClient.Post("https://uniregistrar.io/1.0/create?method=ion", "application/json", bytes.NewReader(req))
	if err != nil {
		return nil, err
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			fmt.Println(err.Error())
		}
	}()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	uniRegistrarResponse := &uniRegistrarResponse{}

	if err := json.Unmarshal(payload, uniRegistrarResponse); err != nil {
		return nil, err
	}

	longFormDID := strings.ReplaceAll(uniRegistrarResponse.DIDDocumentMetadata.LongFormDid, "test:", "")

	return &createResult{
		didID:   longFormDID,
		creator: longFormDID + vm.ID,
	}, nil
}

func newVerMethods(count int, km KeysCreator, verMethodType vcsverifiable.SignatureType,
	keyType kms.KeyType) ([]*did.VerificationMethod, error) {
	methods := make([]*did.VerificationMethod, count)

	for i := 0; i < count; i++ {
		keyID, j, err := km.CreateJWKKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("failed to create key: %w", err)
		}

		// TODO sidetree doesn't support VM controller: https://github.com/decentralized-identity/sidetree/issues/1010
		vm, err := did.NewVerificationMethodFromJWK(
			keyID,
			signatureTypeToDidVerificationMethod[verMethodType],
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
