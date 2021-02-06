/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/stretchr/testify/require"
	zcapld2 "github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/zcapld"
)

func TestNewHTTPSigner(t *testing.T) {
	t.Run("E2E signature computation and verification", func(t *testing.T) {
		agent := newAgent(t)
		verMethod := newVerMethod(t, agent.KMS())
		sign := zcapld.NewHTTPSigner(
			verMethod,
			"mockZCAP",
			&zcapld.DIDSecrets{
				Secrets: map[string]httpsignatures.Secrets{
					"key": &zcapld2.AriesDIDKeySecrets{},
				},
			},
			&zcapld.DIDSignatureHashAlgorithms{
				KMS:       agent.KMS(),
				Crypto:    agent.Crypto(),
				Resolvers: []zcapld.DIDResolver{key.New()},
			},
		)
		request := httptest.NewRequest(http.MethodGet, "/some/path", nil)
		headers, err := sign(request)
		require.NoError(t, err)
		require.NotEmpty(t, headers.Get("capability-invocation"))
		require.NotEmpty(t, headers.Get("signature"))

		request.Header = *headers

		hs := httpsignatures.NewHTTPSignatures(&zcapld.DIDSecrets{
			Secrets: map[string]httpsignatures.Secrets{
				"key": &zcapld2.AriesDIDKeySecrets{},
			},
		})
		hs.SetSignatureHashAlgorithm(&zcapld.DIDSignatureHashAlgorithms{
			KMS:       agent.KMS(),
			Crypto:    agent.Crypto(),
			Resolvers: []zcapld.DIDResolver{key.New()},
		})

		err = hs.Verify(request)
		require.NoError(t, err)
	})

	t.Run("wraps signature error", func(t *testing.T) {
		expected := errors.New("test error")
		agent := newAgent(t)
		verMethod := newVerMethod(t, agent.KMS())
		sign := zcapld.NewHTTPSigner(
			verMethod,
			"mockZCAP",
			&zcapld.DIDSecrets{
				Secrets: map[string]httpsignatures.Secrets{
					"key": &zcapld2.AriesDIDKeySecrets{},
				},
			},
			&zcapld.DIDSignatureHashAlgorithms{
				KMS:       &mockkms.KeyManager{GetKeyErr: expected},
				Crypto:    agent.Crypto(),
				Resolvers: []zcapld.DIDResolver{key.New()},
			},
		)
		request := httptest.NewRequest(http.MethodGet, "/some/path", nil)
		_, err := sign(request)
		require.Error(t, err)
		require.Contains(t, err.Error(), expected.Error())
	})
}

func TestDIDSecrets_Get(t *testing.T) {
	t.Run("returns secret", func(t *testing.T) {
		expected := httpsignatures.Secret{
			KeyID:      uuid.New().String(),
			PublicKey:  uuid.New().String(),
			PrivateKey: uuid.New().String(),
			Algorithm:  uuid.New().String(),
		}
		d := &zcapld.DIDSecrets{
			Secrets: map[string]httpsignatures.Secrets{
				"example": &mockSecrets{s: expected},
			},
		}
		result, err := d.Get("did:example:abc#123")
		require.NoError(t, err)

		require.Equal(t, expected.PublicKey, result.PublicKey)
		require.Equal(t, expected.KeyID, result.KeyID)
		require.Equal(t, expected.PrivateKey, result.PrivateKey)
	})

	t.Run("error if did method not supported", func(t *testing.T) {
		d := &zcapld.DIDSecrets{}
		_, err := d.Get("did:example:abc#123")
		require.EqualError(t, err, "unsupported DID method: example")
	})

	t.Run("error if DID is malformed", func(t *testing.T) {
		d := &zcapld.DIDSecrets{}
		_, err := d.Get("did:malformed#123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse DID")
	})

	t.Run("wraps error from underlying secrets store", func(t *testing.T) {
		expected := errors.New("test")
		d := &zcapld.DIDSecrets{
			Secrets: map[string]httpsignatures.Secrets{
				"example": &mockSecrets{e: expected},
			},
		}
		_, err := d.Get("did:example:abc#123")
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestDIDSignatureHashAlgorithms_CommonTests(t *testing.T) {
	t.Run("creates and verifies signatures", func(t *testing.T) {
		t.Run("using Ed25519", func(t *testing.T) {
			t.Run("in did:key", func(t *testing.T) {
				agent := newAgent(t)

				_, pubKeyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
				require.NoError(t, err)

				_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

				a := &zcapld.DIDSignatureHashAlgorithms{
					KMS:       agent.KMS(),
					Crypto:    agent.Crypto(),
					Resolvers: []zcapld.DIDResolver{key.New()},
				}

				msg := []byte("hello world")
				secret := httpsignatures.Secret{KeyID: didKeyURL}

				signature, err := a.Create(secret, msg)
				require.NoError(t, err)
				require.NotEmpty(t, signature)

				err = a.Verify(secret, msg, signature)
				require.NoError(t, err)
			})
		})
	})

	t.Run("fails if keyID is not a didURL", func(t *testing.T) {
		a := &zcapld.DIDSignatureHashAlgorithms{}
		secret := httpsignatures.Secret{KeyID: "invalid"}

		_, err := a.Create(secret, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a did URL")

		err = a.Verify(secret, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a did URL")
	})

	t.Run("fails if did method is not supported", func(t *testing.T) {
		a := &zcapld.DIDSignatureHashAlgorithms{}
		secret := httpsignatures.Secret{KeyID: "did:unsupported:abc#123"}

		_, err := a.Create(secret, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no resolver configured for method")

		err = a.Verify(secret, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no resolver configured for method")
	})

	t.Run("fails if resolver cannot resolve did doc", func(t *testing.T) {
		expected := errors.New("test")
		method := "test"
		a := &zcapld.DIDSignatureHashAlgorithms{
			Resolvers: []zcapld.DIDResolver{
				&mockDIDResolver{
					method:  method,
					readErr: expected,
				},
			},
		}

		secret := httpsignatures.Secret{KeyID: fmt.Sprintf("did:%s:abc#123", method)}

		_, err := a.Create(secret, nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))

		err = a.Verify(secret, nil, nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("fails if verification method cannot be de-referenced from did doc", func(t *testing.T) {
		agent := newAgent(t)
		method, err := peer.New(mem.NewProvider())
		require.NoError(t, err)
		resolution, err := method.Create(agent.KMS(), &did.Doc{})
		require.NoError(t, err)

		a := &zcapld.DIDSignatureHashAlgorithms{
			KMS:       agent.KMS(),
			Crypto:    agent.Crypto(),
			Resolvers: []zcapld.DIDResolver{method},
		}

		secret := httpsignatures.Secret{KeyID: fmt.Sprintf("%s#%s", resolution.DIDDocument.ID, uuid.New().String())}

		_, err = a.Create(secret, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to dereference")

		err = a.Verify(secret, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to dereference")
	})

	t.Run("fails if the verificationMethod type is not supported", func(t *testing.T) {
		agent := newAgent(t)

		const doc = `{
  			"@context": ["https://w3id.org/did/v1"],
  			"id": "did:example:21tDAKCERh95uGgKbJNHYp",
  			"capabilityDelegation": [{
      			"id": "did:example:21tDAKCERh95uGgKbJNHYp#key1",
      			"type": "UNSUPPORTED",
      			"controller": "did:example:21tDAKCERh95uGgKbJNHYp",
      			"publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
  			}]
		}`
		ddoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		//secret := httpsignatures.Secret{KeyID: fmt.Sprintf("%s#%s", ddoc.ID, delegationMethod.ID)}
		secret := httpsignatures.Secret{KeyID: "did:example:21tDAKCERh95uGgKbJNHYp#key1"}

		a := &zcapld.DIDSignatureHashAlgorithms{
			KMS:    agent.KMS(),
			Crypto: agent.Crypto(),
			Resolvers: []zcapld.DIDResolver{&mockDIDResolver{
				method:    "example",
				readValue: &did.DocResolution{DIDDocument: ddoc},
			}},
		}

		_, err = a.Create(secret, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported verificationMethod type")

		err = a.Verify(secret, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported verificationMethod type")
	})
}

func TestDIDSignatureHashAlgorithms_Create(t *testing.T) {
	t.Run("fails if KMS cannot fetch the key", func(t *testing.T) {
		expected := errors.New("test")

		agent := newAgent(t)

		_, pubKeyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

		a := &zcapld.DIDSignatureHashAlgorithms{
			KMS:       &mockkms.KeyManager{GetKeyErr: expected},
			Resolvers: []zcapld.DIDResolver{key.New()},
		}

		secret := httpsignatures.Secret{KeyID: didKeyURL}

		_, err = a.Create(secret, nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("fails if crypto cannot sign the message", func(t *testing.T) {
		expected := errors.New("test")

		agent := newAgent(t)

		_, pubKeyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

		a := &zcapld.DIDSignatureHashAlgorithms{
			KMS:       agent.KMS(),
			Crypto:    &mockcrypto.Crypto{SignErr: expected},
			Resolvers: []zcapld.DIDResolver{key.New()},
		}

		secret := httpsignatures.Secret{KeyID: didKeyURL}

		_, err = a.Create(secret, nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestDIDSignatureHashAlgorithms_Verify(t *testing.T) {
	t.Run("fails on invalid signature", func(t *testing.T) {
		agent := newAgent(t)

		_, pubKeyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

		a := &zcapld.DIDSignatureHashAlgorithms{
			KMS:       agent.KMS(),
			Crypto:    agent.Crypto(),
			Resolvers: []zcapld.DIDResolver{key.New()},
		}

		msg := []byte(uuid.New().String())
		secret := httpsignatures.Secret{KeyID: didKeyURL}

		_, err = a.Create(secret, msg)
		require.NoError(t, err)

		err = a.Verify(secret, msg, []byte("INVALID"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify signature")
	})

	t.Run("fails if kms cannot convert pub key bytes to handle", func(t *testing.T) {
		expected := errors.New("test")

		agent := newAgent(t)

		_, pubKeyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

		a := &zcapld.DIDSignatureHashAlgorithms{
			KMS:       &mockkms.KeyManager{PubKeyBytesToHandleErr: expected},
			Crypto:    agent.Crypto(),
			Resolvers: []zcapld.DIDResolver{key.New()},
		}

		secret := httpsignatures.Secret{KeyID: didKeyURL}

		err = a.Verify(secret, nil, nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func newVerMethod(t *testing.T, k kms.KeyManager) string {
	_, pubKeyBytes, err := k.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func newAgent(t *testing.T) *context.Provider {
	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

type mockSecrets struct {
	s httpsignatures.Secret
	e error
}

func (m *mockSecrets) Get(string) (httpsignatures.Secret, error) {
	return m.s, m.e
}

type mockDIDResolver struct {
	method    string
	readValue *did.DocResolution
	readErr   error
}

func (m *mockDIDResolver) Accept(method string) bool {
	return m.method == method
}

func (m *mockDIDResolver) Read(string, ...vdr.ResolveOption) (*did.DocResolution, error) {
	return m.readValue, m.readErr
}
