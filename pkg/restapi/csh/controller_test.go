/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csh_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	did2 "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/restapi/csh"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
)

func TestNew(t *testing.T) {
	t.Run("returns an instance", func(t *testing.T) {
		c, err := csh.New(config(t))
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestController_GetOperations(t *testing.T) {
	c, err := csh.New(config(t))
	require.NoError(t, err)
	require.True(t, len(c.GetOperations()) > 0)
}

func config(t *testing.T) *operation.Config {
	t.Helper()

	return &operation.Config{
		StoreProvider: mem.NewProvider(),
		Aries: &operation.AriesConfig{
			KMS:    &mockkms.KeyManager{},
			Crypto: &mockcrypto.Crypto{},
			PublicDIDCreator: func(kms.KeyManager) (*did2.DocResolution, error) {
				id := fmt.Sprintf("did:example:%s", uuid.New().String())

				return &did2.DocResolution{
					DIDDocument: &did2.Doc{
						ID:      id,
						Context: []string{did2.Context},
						Authentication: []did2.Verification{{
							VerificationMethod: did2.VerificationMethod{
								ID: id + "#key-1",
							},
							Relationship: did2.Authentication,
							Embedded:     true,
						}},
						CapabilityDelegation: []did2.Verification{{
							VerificationMethod: did2.VerificationMethod{
								ID: id + "#key-2",
							},
							Relationship: did2.CapabilityDelegation,
							Embedded:     true,
						}},
						CapabilityInvocation: []did2.Verification{{
							VerificationMethod: did2.VerificationMethod{
								ID: id + "#key-3",
							},
							Relationship: did2.CapabilityInvocation,
							Embedded:     true,
						}},
					},
				}, nil
			},
		},
	}
}
