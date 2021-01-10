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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"
	corestorage "github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	testProfileID = "testProfileID"
	validContext  = `"@context":["https://www.w3.org/2018/credentials/v1"]`
	domain        = "domain"
	challenge     = "challenge"
)

func TestCreateHolderProfile(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:        customCrypto,
		StoreProvider: memstore.NewProvider(),
		KeyManager:    customKMS,
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	op.commonDID = &mockCommonDID{}

	endpoint := holderProfileEndpoint
	handler := getHandler(t, op, endpoint, http.MethodPost)

	t.Run("create profile - success", func(t *testing.T) {
		vReq := &HolderProfileRequest{
			Name:          "test",
			DIDKeyType:    vccrypto.Ed25519KeyType,
			SignatureType: vccrypto.Ed25519Signature2018,
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		profileRes := &HolderProfileRequest{}
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
		vReq := &HolderProfileRequest{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile name")
	})

	t.Run("create profile - profile already exists", func(t *testing.T) {
		vReq := &HolderProfileRequest{
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

	t.Run("create profile - failed to created DID", func(t *testing.T) {
		ops, err := New(&Config{
			Crypto:        customCrypto,
			StoreProvider: memstore.NewProvider(),
			KeyManager:    customKMS,
			VDRI:          &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)

		vReq := &HolderProfileRequest{
			Name: "profile",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		handler := getHandler(t, ops, endpoint, http.MethodPost)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did public key")
	})
}

func TestGetHolderProfile(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:        customCrypto,
		StoreProvider: memstore.NewProvider(),
		KeyManager:    customKMS,
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	op.commonDID = &mockCommonDID{}

	endpoint := getHolderProfileEndpoint
	handler := getHandler(t, op, endpoint, http.MethodGet)

	urlVars := make(map[string]string)

	t.Run("get profile - success", func(t *testing.T) {
		vReq := &vcprofile.HolderProfile{
			DataProfile: &vcprofile.DataProfile{
				Name:          "test",
				SignatureType: vccrypto.Ed25519Signature2018,
			},
		}

		err := op.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		urlVars[profileIDPathParam] = vReq.Name

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)

		profileRes := &HolderProfileRequest{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, vReq.Name, profileRes.Name)
	})

	t.Run("get profile - no data found", func(t *testing.T) {
		urlVars[profileIDPathParam] = "invalid-name"

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		fmt.Println(rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "store does not have a value associated with this key")
	})
}

func TestDeleteHolderProfileHandler(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: memstore.NewProvider(),
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	endpoint := deleteHolderProfileEndpoint
	handler := getHandler(t, op, endpoint, http.MethodDelete)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = testProfileID

	t.Run("delete profile - success", func(t *testing.T) {
		saveTestProfile(t, op)

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("delete profile - profile does not exist", func(t *testing.T) {
		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Contains(t, rr.Body.String(),
			fmt.Sprintf("Holder profile with id %s does not exist: %s",
				testProfileID, corestorage.ErrValueNotFound))
	})

	t.Run("delete profile - delete same profile twice", func(t *testing.T) {
		saveTestProfile(t, op)

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)
		require.Equal(t, http.StatusOK, rr.Code)

		rr = serveHTTPMux(t, handler, endpoint, nil, urlVars)
		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Contains(t, rr.Body.String(),
			fmt.Sprintf("Holder profile with id %s does not exist: %s",
				testProfileID, corestorage.ErrValueNotFound))
	})

	t.Run("delete profile - other error in delete profile from store", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{
				Store:     make(map[string][]byte),
				ErrDelete: errors.New("delete error")},
			},
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)
		handler := getHandler(t, op, endpoint, http.MethodDelete)

		saveTestProfile(t, op)
		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "delete error")
	})
}

func TestSignPresentation(t *testing.T) {
	endpoint := "/test/prove/presentations"
	keyID := "key-333"

	vReq := &vcprofile.HolderProfile{
		DataProfile: &vcprofile.DataProfile{
			Name:          "test",
			SignatureType: vccrypto.Ed25519Signature2018,
			Creator:       "did:test:abc#" + keyID,
		},
	}

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider: memstore.NewProvider(),
		KeyManager:    customKMS,
		Crypto:        customCrypto,
	})
	require.NoError(t, err)

	err = op.profileStore.SaveHolderProfile(vReq)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = vReq.Name

	handler := getHandler(t, op, signPresentationEndpoint, http.MethodPost)

	t.Run("sign presentation - success", func(t *testing.T) {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kid, _, err := customKMS.ImportPrivateKey(privKey, kms.ED25519Type, kms.WithKeyID(keyID))
		require.NoError(t, err)
		require.Equal(t, kid, keyID)

		signingKey, err := customKMS.ExportPubKeyBytes(kid)
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KeyManager:    customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDocWithKeyID(didID, keyID, signingKey), nil
				},
			},
			Crypto: customCrypto,
		})
		require.NoError(t, err)

		vReq.SignatureRepresentation = verifiable.SignatureJWS
		vReq.OverwriteHolder = true
		vReq.DID = "did:trustbloc:xyz"

		err = ops.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, signPresentationEndpoint, http.MethodPost)

		require.NoError(t, err)

		req := &SignPresentationRequest{
			Presentation: []byte(vpWithoutProof),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVPResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVPResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVPResp["proof"])
		require.Equal(t, vReq.DID, signedVPResp["holder"])

		proof, ok := signedVPResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:test:abc#"+keyID, proof["verificationMethod"])
		require.Equal(t, vccrypto.Authentication, proof["proofPurpose"])

		// pass proof purpose option
		req = &SignPresentationRequest{
			Presentation: []byte(vpWithoutProof),
			Opts: &SignPresentationOptions{
				ProofPurpose: vccrypto.AssertionMethod,
			},
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, signPresentationHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVPResp = make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVPResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVPResp["proof"])

		proof, ok = signedVPResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:test:abc#"+keyID, proof["verificationMethod"])
		require.Equal(t, vccrypto.AssertionMethod, proof["proofPurpose"])
	})

	t.Run("sign presentation - success with opts", func(t *testing.T) {
		customKMS2 := createKMS(t)
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kid, _, err := customKMS2.ImportPrivateKey(privKey, kms.ED25519Type, kms.WithKeyID(keyID))
		require.NoError(t, err)
		require.Equal(t, kid, keyID)

		signingKey, err := customKMS2.ExportPubKeyBytes(kid)
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KeyManager:    customKMS2,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDocWithKeyID(didID, keyID, signingKey), nil
				},
			},
			Crypto: customCrypto,
		})
		require.NoError(t, err)

		vReq.SignatureRepresentation = verifiable.SignatureJWS

		err = ops.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, signPresentationEndpoint, http.MethodPost)

		proofPurposeVal := "authentication"

		req := &SignPresentationRequest{
			Presentation: []byte(vpWithoutProof),
			Opts: &SignPresentationOptions{
				Challenge:       challenge,
				Domain:          domain,
				ProofPurpose:    proofPurposeVal,
				AssertionMethod: "did:example:xyz#" + keyID,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVCResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok := signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:example:xyz#"+keyID, proof["verificationMethod"])
		require.Equal(t, proofPurposeVal, proof["proofPurpose"])
		require.Equal(t, domain, proof[domain])
		require.Equal(t, challenge, proof[challenge])
	})

	t.Run("sign presentation - invalid profile", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			Crypto:        customCrypto,
			KeyManager:    customKMS,
		})
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, signPresentationEndpoint, http.MethodPost)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid holder profile")
	})

	t.Run("sign presentation - invalid request", func(t *testing.T) {
		rr := serveHTTPMux(t, handler, endpoint, []byte("invalid json"), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), invalidRequestErrMsg)
	})

	t.Run("sign presentation - invalid presentation", func(t *testing.T) {
		req := &SignPresentationRequest{
			Presentation: []byte(vc),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable presentation is not valid")
	})

	t.Run("sign presentation - signing error", func(t *testing.T) {
		op, err := New(&Config{
			Crypto:        customCrypto,
			StoreProvider: memstore.NewProvider(),
			KeyManager:    customKMS,
			VDRI:          &vdrmock.MockVDRegistry{ResolveErr: errors.New("resolve error")},
		})
		require.NoError(t, err)

		vReq.Creator = "not a did"

		err = op.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, op, signPresentationEndpoint, http.MethodPost)

		req := &SignPresentationRequest{
			Presentation: []byte(vpWithoutProof),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign presentation")
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

func getHandler(t *testing.T, op *Operation, lookupPath, methodToLookup string) Handler {
	return getHandlerWithError(t, op, lookupPath, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookupPath, methodToLookup string) Handler {
	return handlerLookup(t, op, lookupPath, methodToLookup)
}

func handlerLookup(t *testing.T, op *Operation, lookupPath, methodToLookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookupPath && h.Method() == methodToLookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTPMux(t *testing.T, handler Handler, endpoint string, reqBytes []byte,
	urlVars map[string]string) *httptest.ResponseRecorder {
	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
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

func saveTestProfile(t *testing.T, op *Operation) {
	vReq := &vcprofile.HolderProfile{
		DataProfile: &vcprofile.DataProfile{
			Name: testProfileID,
		},
	}

	err := op.profileStore.SaveHolderProfile(vReq)
	require.NoError(t, err)
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

const (
	vpWithoutProof = `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		"type": "VerifiablePresentation",
		"verifiableCredential": [{
			"@context": [
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1",
				"https://trustbloc.github.io/context/vc/examples-v1.jsonld"
			],
			"id": "http://example.edu/credentials/1872",
			"type": "VerifiableCredential",
			"credentialSubject": {
				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
			},
			"issuer": {
				"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
				"name": "Example University"
			},
			"issuanceDate": "2010-01-01T19:23:24Z",
			"credentialStatus": {
				"id": "https://example.gov/status/24",
				"type": "CredentialStatusList2017"
			}
		}],
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"refreshService": {
			"id": "https://example.edu/refresh/3732",
			"type": "ManualRefreshService2018"
		}
	}`

	vc = `{` +
		validContext + `,
	  "id": "http://example.edu/credentials/1872",
	  "type": "VerifiableCredential",
	  "credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	  },
	  "issuanceDate": "2010-01-01T19:23:24Z"
	}`
)

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}
