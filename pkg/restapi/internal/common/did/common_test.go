/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"
	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"
	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"

	"github.com/trustbloc/edge-service/pkg/client/uniregistrar"
	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

func TestCommonDID_ResolveDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{},
			VDRI: &vdr.MockVDRegistry{ResolveValue: &ariesdid.Doc{ID: "did:test:123"}}})

		did, keyID, err := c.CreateDID("", "", "did:test:123", base58.Encode([]byte("key")),
			"did:test:123#key1", crypto.Authentication, model.UNIRegistrar{})

		require.NoError(t, err)
		require.Equal(t, "did:test:123#key1", keyID)
		require.Equal(t, "did:test:123", did)
	})

	t.Run("test error - resolve DID", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{},
			VDRI: &vdr.MockVDRegistry{ResolveErr: fmt.Errorf("failed to resolve did")}})

		did, keyID, err := c.CreateDID("", "", "did:test:123", base58.Encode([]byte("key")),
			"did:test:123#key1", crypto.Authentication, model.UNIRegistrar{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - import private key", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{ImportPrivateKeyErr: fmt.Errorf("failed to import key")},
			VDRI: &vdr.MockVDRegistry{ResolveValue: &ariesdid.Doc{ID: "did:test:123"}}})

		did, keyID, err := c.CreateDID("", "", "did:test:123", base58.Encode([]byte("key")),
			"did:test:123#key1", crypto.Authentication, model.UNIRegistrar{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to import key")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})
}

func TestCommonDID_CreateDID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.trustBlocDIDClient = &mockTrustBlocDIDClient{CreateDIDValue: &ariesdid.Doc{ID: "did:trustbloc:123"}}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{})

		require.NoError(t, err)
		require.Equal(t, "did:trustbloc:123#key-1", keyID)
		require.Equal(t, "did:trustbloc:123", did)
	})

	t.Run("test error - create public keys failed", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.Ed25519Signature2018, "", "",
			"", crypto.Authentication, model.UNIRegistrar{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "no key found to match key type:P256 and signature type:Ed25519Signature2018")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - create did failed", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.trustBlocDIDClient = &mockTrustBlocDIDClient{CreateDIDErr: fmt.Errorf("failed to create DID")}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create DID")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})
}
func TestCommonDID_CreateDIDUniRegistrar(t *testing.T) {
	t.Run("test success - trustbloc method", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDValue: "did:trustbloc:123",
			CreateDIDKeys: []didmethodoperation.Key{{ID: "did:trustbloc:123#key-1"}, {ID: "did:trustbloc:123#key2"}}}

		did, keyID, err := c.CreateDID(crypto.P256KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.NoError(t, err)
		require.Equal(t, "did:trustbloc:123#key-1", keyID)
		require.Equal(t, "did:trustbloc:123", did)
	})

	t.Run("test error - trustbloc method key not found", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-3"}})

		c.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDValue: "did:trustbloc:123",
			CreateDIDKeys: []didmethodoperation.Key{{ID: "did:trustbloc:123#key-1"}, {ID: "did:trustbloc:123#key2"}}}

		did, keyID, err := c.CreateDID(crypto.Ed25519KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.Error(t, err)
		require.Contains(t, err.Error(), "selected key not found key-3")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test success - v1 method", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDValue: "did:v1:123",
			CreateDIDKeys: []didmethodoperation.Key{{ID: "did:v1:123#key-1", Purpose: []string{crypto.AssertionMethod}},
				{ID: "did:v1:123#key2", Purpose: []string{crypto.Authentication}}}}

		did, keyID, err := c.CreateDID(crypto.Ed25519KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.NoError(t, err)
		require.Equal(t, "did:v1:123#key2", keyID)
		require.Equal(t, "did:v1:123", did)
	})

	t.Run("test error - v1 method key not found", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDValue: "did:v1:123",
			CreateDIDKeys: []didmethodoperation.Key{{ID: "did:v1:123#key-1", Purpose: []string{crypto.AssertionMethod}},
				{ID: "did:v1:123#key2", Purpose: []string{crypto.AssertionMethod}}}}

		did, keyID, err := c.CreateDID(crypto.Ed25519KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.Error(t, err)
		require.Contains(t, err.Error(), "did:v1 - not able to find key with purpose authentication")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test success - other did methods", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDValue: "did:test:123",
			CreateDIDKeys: []didmethodoperation.Key{{ID: "did:test:123#key-1", Purpose: []string{crypto.AssertionMethod}},
				{ID: "did:test:123#key2", Purpose: []string{crypto.Authentication}}}}

		did, keyID, err := c.CreateDID(crypto.Ed25519KeyType, crypto.Ed25519Signature2018, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.NoError(t, err)
		require.Equal(t, "did:test:123#key-1", keyID)
		require.Equal(t, "did:test:123", did)
	})

	t.Run("test error - create public keys failed", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyErr: fmt.Errorf("failed create key")}})

		did, keyID, err := c.CreateDID(crypto.Ed25519KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed create key")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})

	t.Run("test error - create did through uni registrar failed", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{CreateKeyID: "key-1"}})

		c.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDErr: fmt.Errorf("failed create DID")}

		did, keyID, err := c.CreateDID(crypto.Ed25519KeyType, crypto.JSONWebSignature2020, "", "",
			"", crypto.Authentication, model.UNIRegistrar{DriverURL: "url"})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed create DID")
		require.Empty(t, keyID)
		require.Empty(t, did)
	})
}

func TestCommonDID_CreateKey(t *testing.T) {
	t.Run("test error - export public key failed", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{ExportPubKeyBytesErr: fmt.Errorf("failed export public key")}})
		_, _, err := c.createKey("ED25519")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed export public key")
	})
}

func TestCommonDID_ImportKey(t *testing.T) {
	t.Run("test error - key type not supported", func(t *testing.T) {
		c := New(&Config{KeyManager: &mockkms.KeyManager{}})
		err := c.importKey("", "wrongType", []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "import key type not supported wrongType")
	})
}

type mockUNIRegistrarClient struct {
	CreateDIDValue string
	CreateDIDKeys  []didmethodoperation.Key
	CreateDIDErr   error
}

func (m *mockUNIRegistrarClient) CreateDID(driverURL string,
	opts ...uniregistrar.CreateDIDOption) (string, []didmethodoperation.Key, error) {
	return m.CreateDIDValue, m.CreateDIDKeys, m.CreateDIDErr
}

type mockTrustBlocDIDClient struct {
	CreateDIDValue *ariesdid.Doc
	CreateDIDErr   error
}

func (m *mockTrustBlocDIDClient) CreateDID(domain string, opts ...didclient.CreateDIDOption) (*ariesdid.Doc, error) {
	return m.CreateDIDValue, m.CreateDIDErr
}
