/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

// Config configures PublicDID.
type Config struct {
	Method                 string
	VerificationMethodType string
	VDR                    vdr.Registry
	JWKKeyCreator          func(kms.KeyManager) (string, *jose.JWK, error)
	CryptoKeyCreator       func(kms.KeyManager) (string, interface{}, error)
	DIDAnchorOrigin        string
}

// PublicDID creates a new public DID given a Config and a key manager.
func PublicDID(config *Config) func(kms.KeyManager) (*did.DocResolution, error) {
	return func(km kms.KeyManager) (*did.DocResolution, error) {
		methods := map[string]func(kms.KeyManager, *Config) (*did.DocResolution, error){
			key.DIDMethod: keyDID,
			orb.DIDMethod: createDID,
		}

		method, supported := methods[config.Method]
		if !supported {
			return nil, fmt.Errorf("unsupported did method: %s", config.Method)
		}

		return method(km, config)
	}
}

func createDID(km kms.KeyManager, config *Config) (*did.DocResolution, error) {
	methods, err := newVerMethods(3, km, config.VerificationMethodType, config.JWKKeyCreator) // nolint:gomnd
	if err != nil {
		return nil, fmt.Errorf("did:trustbloc: failed to create verification methods: %w", err)
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
	types := [2]string{"update", "recovery"}

	for i := 0; i < 2; i++ {
		_, keys[i], err = config.CryptoKeyCreator(km)
		if err != nil {
			return nil, fmt.Errorf("did:trustbloc: failed to create %s key: %w", types[i], err)
		}
	}

	updateKey := keys[0]
	recoveryKey := keys[1]

	// TODO what to do with updateKey and recoveryKey... ?
	return config.VDR.Create(
		orb.DIDMethod,
		doc,
		vdr.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdr.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdr.WithOption(orb.AnchorOriginOpt, config.DIDAnchorOrigin),
	)
}

func keyDID(km kms.KeyManager, config *Config) (*did.DocResolution, error) {
	verMethod, err := newVerMethods(1, km, config.VerificationMethodType, config.JWKKeyCreator)
	if err != nil {
		return nil, fmt.Errorf("did:key: failed to create new ver method: %w", err)
	}

	return config.VDR.Create(
		key.DIDMethod,
		&did.Doc{
			VerificationMethod: []did.VerificationMethod{*verMethod[0]},
		},
	)
}

func newVerMethods(
	count int, km kms.KeyManager, verMethodType string,
	keyCreator func(kms.KeyManager) (string, *jose.JWK, error)) ([]*did.VerificationMethod, error) {
	methods := make([]*did.VerificationMethod, count)

	for i := 0; i < count; i++ {
		keyID, jwk, err := keyCreator(km)
		if err != nil {
			return nil, fmt.Errorf("failed to create key: %w", err)
		}

		// TODO sidetree doesn't support VM controller: https://github.com/decentralized-identity/sidetree/issues/1010
		vm, err := did.NewVerificationMethodFromJWK(
			keyID,
			verMethodType,
			"",
			jwk,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create verification method: %w", err)
		}

		methods[i] = vm
	}

	return methods, nil
}
