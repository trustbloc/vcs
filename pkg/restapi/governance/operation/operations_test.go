/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

func TestCreateGovernanceProfile(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:        customCrypto,
		StoreProvider: ariesmemstorage.NewProvider(),
		KeyManager:    customKMS,
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	op.commonDID = &mockCommonDID{}

	endpoint := governanceProfileEndpoint
	handler := getHandler(t, op, endpoint)

	t.Run("create profile - success", func(t *testing.T) {
		vReq := &GovernanceProfileRequest{
			Name:          "test",
			DIDKeyType:    vccrypto.Ed25519KeyType,
			SignatureType: vccrypto.Ed25519Signature2018,
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		profileRes := &GovernanceProfileRequest{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, "test", profileRes.Name)
	})

	t.Run("create profile - invalid request", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, []byte("invalid-json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("create profile - missing profile name", func(t *testing.T) {
		vReq := &GovernanceProfileRequest{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile name")
	})

	t.Run("create profile - profile already exists", func(t *testing.T) {
		vReq := &GovernanceProfileRequest{
			Name:          "test1",
			DIDKeyType:    vccrypto.Ed25519KeyType,
			SignatureType: vccrypto.Ed25519Signature2018,
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "profile test1 already exists")
	})

	t.Run("create profile - failed to get profile", func(t *testing.T) {
		op, err := New(&Config{
			Crypto: customCrypto,
			StoreProvider: &ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
				Store: map[string]ariesmockstorage.DBEntry{
					"profile_governance_test1": {Value: []byte("")},
				},
				ErrGet: fmt.Errorf("failed to get"),
			}},
			KeyManager: customKMS,
			VDRI:       &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)

		op.commonDID = &mockCommonDID{}

		handler := getHandler(t, op, governanceProfileEndpoint)

		vReq := &GovernanceProfileRequest{
			Name:          "test1",
			DIDKeyType:    vccrypto.Ed25519KeyType,
			SignatureType: vccrypto.Ed25519Signature2018,
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get")
	})

	t.Run("create profile - failed to store governance profile", func(t *testing.T) {
		op, err := New(&Config{
			Crypto: customCrypto,
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					Store:  make(map[string]ariesmockstorage.DBEntry),
					ErrPut: fmt.Errorf("failed to put"),
				},
			},
			KeyManager: customKMS,
			VDRI:       &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)

		op.commonDID = &mockCommonDID{}

		handler := getHandler(t, op, endpoint)

		vReq := &GovernanceProfileRequest{
			Name:          "test1",
			DIDKeyType:    vccrypto.Ed25519KeyType,
			SignatureType: vccrypto.Ed25519Signature2018,
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to put")
	})

	t.Run("create profile - failed to created DID", func(t *testing.T) {
		ops, err := New(&Config{
			Crypto:        customCrypto,
			StoreProvider: ariesmemstorage.NewProvider(),
			KeyManager:    customKMS,
			VDRI:          &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)

		vReq := &GovernanceProfileRequest{
			Name: "profile",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		handler := getHandler(t, ops, endpoint)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did public key")
	})
}

func TestIssueCredential(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	file, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(`{"name":"claim"}`)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	keyID := "key-333"

	vReq := &vcprofile.GovernanceProfile{
		DataProfile: &vcprofile.DataProfile{
			Name:                    "test",
			SignatureType:           vccrypto.Ed25519Signature2018,
			Creator:                 "did:test:abc#" + keyID,
			SignatureRepresentation: verifiable.SignatureJWS,
		},
	}

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = vReq.Name

	t.Run("issue credential - success", func(t *testing.T) {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kid, _, err := customKMS.ImportPrivateKey(privKey, kms.ED25519Type, kms.WithKeyID(keyID))
		require.NoError(t, err)
		require.Equal(t, keyID, kid)

		signingKey, err := customKMS.ExportPubKeyBytes(keyID)
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider: ariesmemstorage.NewProvider(),
			KeyManager:    customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.ResolveOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, signingKey)}, nil
				},
			},
			Crypto:     customCrypto,
			ClaimsFile: file.Name(),
		})
		require.NoError(t, err)

		err = ops.profileStore.SaveGovernanceProfile(vReq)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialHandler)

		require.NoError(t, err)

		req := &IssueCredentialRequest{
			DID: "did:example:123",
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		vc := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &vc)
		require.NoError(t, err)
		require.NotEmpty(t, vc["proof"])

		proof, ok := vc["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:test:abc#"+keyID, proof["verificationMethod"])
		require.Equal(t, vccrypto.AssertionMethod, proof["proofPurpose"])

		credentialSubject, ok := vc["credentialSubject"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "claim", credentialSubject["name"])
	})

	t.Run("issue credential - failed to get governance", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
				Store: map[string]ariesmockstorage.DBEntry{
					"profile_governance_test1": {Value: []byte("")},
				},
				ErrGet: fmt.Errorf("failed to get"),
			}},
			KeyManager: customKMS,
			VDRI:       &vdrmock.MockVDRegistry{},
			Crypto:     customCrypto,
			ClaimsFile: file.Name(),
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialHandler)

		require.NoError(t, err)

		req := &IssueCredentialRequest{
			DID: "did:example:123",
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid governance profile")
	})

	t.Run("issue credential - failed to create status id", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider: ariesmemstorage.NewProvider(),
			KeyManager:    customKMS,
			VDRI:          &vdrmock.MockVDRegistry{},
			Crypto:        customCrypto,
			ClaimsFile:    file.Name(),
		})
		require.NoError(t, err)

		ops.vcStatusManager = &mockVCStatusManager{createStatusIDErr: fmt.Errorf("failed to create status id")}

		err = ops.profileStore.SaveGovernanceProfile(vReq)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialHandler)

		require.NoError(t, err)

		req := &IssueCredentialRequest{
			DID: "did:example:123",
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to add credential status")
	})

	t.Run("issue credential - failed to sign credential", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider: ariesmemstorage.NewProvider(),
			KeyManager:    customKMS,
			VDRI:          &vdrmock.MockVDRegistry{},
			Crypto:        customCrypto,
			ClaimsFile:    file.Name(),
		})
		require.NoError(t, err)

		ops.vcStatusManager = &mockVCStatusManager{}

		err = ops.profileStore.SaveGovernanceProfile(vReq)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialHandler)

		require.NoError(t, err)

		req := &IssueCredentialRequest{
			DID: "did:example:123",
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign credential")
	})
}

type mockCommonDID struct {
	createDIDValue string
	createDIDKeyID string
	createDIDErr   error
}

func (m *mockCommonDID) CreateDID(keyType, signatureType, didID, privateKey, keyID, purpose string,
	registrar model.UNIRegistrar) (string, string, error) {
	return m.createDIDValue, m.createDIDKeyID, m.createDIDErr
}

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTPMux(t *testing.T, handler Handler, reqBytes []byte,
	urlVars map[string]string) *httptest.ResponseRecorder {
	r, err := http.NewRequest(handler.Method(), "", bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
}

//nolint:unparam
func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder {
	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, httpReq)

	return rr
}

func createDIDDocWithKeyID(didID, keyID string, pubKey []byte) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	creator := didID + "#" + keyID

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: "https://agent.example.com/",
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
	}
}

type mockVCStatusManager struct {
	createStatusIDValue      *verifiable.TypedID
	createStatusIDErr        error
	revokeVCErr              error
	getRevocationListVCValue []byte
	GetRevocationListVCErr   error
}

func (m *mockVCStatusManager) CreateStatusID(profile *vcprofile.DataProfile) (*verifiable.TypedID, error) {
	return m.createStatusIDValue, m.createStatusIDErr
}

func (m *mockVCStatusManager) RevokeVC(v *verifiable.Credential, profile *vcprofile.DataProfile) error {
	return m.revokeVCErr
}

func (m *mockVCStatusManager) GetRevocationListVC(id string) ([]byte, error) {
	return m.getRevocationListVCValue, m.GetRevocationListVCErr
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}
