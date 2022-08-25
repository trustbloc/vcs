/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	webDIDMethod = "web"
)

// CreateResult contains created did, update and recovery keys.
type CreateResult struct {
	DocResolution  *did.DocResolution
	UpdateKeyURL   string
	RecoveryKeyURL string
}

// Creator service used to create public DID.
type Creator struct {
	config *Config
}

// KeysCreator create keys for DID creation process.
type KeysCreator interface {
	CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error)
	CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error)
}

// Config configures PublicDID.
type Config struct {
	VDR             vdr.Registry
	DIDAnchorOrigin string
}

// New creates Creator.
func New(config *Config) *Creator {
	return &Creator{
		config: config,
	}
}

// PublicDID creates a new public DID given a key manager.
func (c *Creator) PublicDID(method, verificationMethodType string, keyType kms.KeyType,
	km KeysCreator) (*CreateResult, error) {
	methods := map[string]func(verificationMethodType string, keyType kms.KeyType, km KeysCreator) (*CreateResult, error){
		key.DIDMethod: c.keyDID,
		orb.DIDMethod: c.createDID,
		webDIDMethod:  c.webDID,
	}

	methodFn, supported := methods[method]
	if !supported {
		return nil, fmt.Errorf("unsupported did method: %s", method)
	}

	return methodFn(verificationMethodType, keyType, km)
}

func (c *Creator) createDID(verificationMethodType string, keyType kms.KeyType, km KeysCreator) (*CreateResult, error) {
	methods, err := newVerMethods(3, km, verificationMethodType, keyType) // nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create verification methods: %w", err)
	}

	authentication := methods[0]
	capabilityDelegation := methods[1]
	capabilityInvocation := methods[2]

	doc := &did.Doc{
		Authentication: []did.Verification{{
			VerificationMethod: *authentication,
			Relationship:       did.Authentication,
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
		keyURLs[i], keys[i], err = km.CreateCryptoKey(kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("did:orb: failed to create %s key: %w", types[i], err)
		}
	}

	updateKey, updateURL := keys[0], keyURLs[0]
	recoveryKey, recoveryURL := keys[1], keyURLs[1]

	// TODO what to do with updateKey and recoveryKey... ?
	didResolution, err := c.config.VDR.Create(
		orb.DIDMethod,
		doc,
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdr.WithOption(orb.AnchorOriginOpt, c.config.DIDAnchorOrigin),
	)

	if err != nil {
		return nil, fmt.Errorf("did:orb: failed to create did: %w", err)
	}

	return &CreateResult{
		DocResolution:  didResolution,
		UpdateKeyURL:   updateURL,
		RecoveryKeyURL: recoveryURL,
	}, nil
}

func (c *Creator) keyDID(verificationMethodType string, keyType kms.KeyType, km KeysCreator) (*CreateResult, error) {
	verMethod, err := newVerMethods(1, km, verificationMethodType, keyType)
	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create new ver method: %w", err)
	}

	didResolution, err := c.config.VDR.Create(
		key.DIDMethod,
		&did.Doc{
			VerificationMethod: []did.VerificationMethod{*verMethod[0]},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create did: %w", err)
	}

	return &CreateResult{
		DocResolution: didResolution,
	}, nil
}

func (c *Creator) webDID(verificationMethodType string, keyType kms.KeyType, km KeysCreator) (*CreateResult, error) {
	return nil, fmt.Errorf("did web method currently not supported, add support in future")
}

func newVerMethods(
	count int, km KeysCreator, verMethodType string, keyType kms.KeyType) ([]*did.VerificationMethod, error) {
	methods := make([]*did.VerificationMethod, count)

	for i := 0; i < count; i++ {
		keyID, j, err := km.CreateJWKKey(keyType)
		if err != nil {
			return nil, fmt.Errorf("failed to create key: %w", err)
		}

		// TODO sidetree doesn't support VM controller: https://github.com/decentralized-identity/sidetree/issues/1010
		vm, err := did.NewVerificationMethodFromJWK(
			keyID,
			verMethodType,
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
