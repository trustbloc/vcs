/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/stretchr/testify/require"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	testProfileID = "testProfileID"
	validContext  = `"@context":["https://www.w3.org/2018/credentials/v1"]`
	domain        = "domain"
	challenge     = "challenge"
	vcForDerive   = `
	{
	 	"@context": [
	   		"https://www.w3.org/2018/credentials/v1",
	   		"https://w3id.org/citizenship/v1",
	   		"https://w3id.org/security/bbs/v1"
	 	],
	 	"id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	 	"type": [
	   		"VerifiableCredential",
	   		"PermanentResidentCard"
	 	],
	 	"issuer": "did:example:489398593",
	 	"identifier": "83627465",
	 	"name": "Permanent Resident Card",
	 	"description": "Government of Example Permanent Resident Card.",
	 	"issuanceDate": "2019-12-03T12:19:52Z",
	 	"expirationDate": "2029-12-03T12:19:52Z",
	 	"credentialSubject": {
	   		"id": "did:example:b34ca6cd37bbf23",
	   		"type": [
	     		"PermanentResident",
	     		"Person"
	   		],
	   		"givenName": "JOHN",
	   		"familyName": "SMITH",
	   		"gender": "Male",
	   		"image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   		"residentSince": "2015-01-01",
	   		"lprCategory": "C09",
	   		"lprNumber": "999-999-999",
	   		"commuterClassification": "C1",
	   		"birthCountry": "Bahamas",
	   		"birthDate": "1958-07-17"
	 	}
	}`

	sampleFrame = `
	{
	"@context": [
    	"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1",
    	"https://w3id.org/security/bbs/v1"
	],
  	"type": ["VerifiableCredential", "PermanentResidentCard"],
  	"@explicit": true,
  	"identifier": {},
  	"issuer": {},
  	"issuanceDate": {},
  	"credentialSubject": {
    	"@explicit": true,
    	"type": ["PermanentResident", "Person"],
    	"givenName": {},
    	"familyName": {},
    	"gender": {}
  	}
	}`
)

func TestCreateHolderProfile(t *testing.T) {
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
			StoreProvider: ariesmemstorage.NewProvider(),
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
		StoreProvider: ariesmemstorage.NewProvider(),
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
		require.Contains(t, rr.Body.String(), "data not found")
	})
}

func TestDeleteHolderProfileHandler(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: ariesmemstorage.NewProvider(),
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

	t.Run("delete profile - other error in delete profile from store", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					Store:     make(map[string]ariesmockstorage.DBEntry),
					ErrDelete: errors.New("delete error"),
				},
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

func TestDeriveCredentials(t *testing.T) {
	endpoint := "/test/credentials/derive"

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = "profile"

	loader := createTestDocumentLoader(t)

	vc, err := verifiable.ParseCredential([]byte(vcForDerive), verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 0)
	didKey := signVCWithBBS(t, vc)
	require.Len(t, vc.Proofs, 1)

	requestVC, err := vc.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, requestVC)

	ops, err := New(&Config{
		StoreProvider: ariesmemstorage.NewProvider(),
		VDRI: &vdrmock.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
				if didID == didKey {
					k := key.New()

					d, e := k.Read(didKey)
					if e != nil {
						return nil, e
					}

					return d, nil
				}

				return nil, fmt.Errorf("did not found")
			},
		},
		DocumentLoader: loader,
	})
	require.NoError(t, err)

	handler := getHandler(t, ops, deriveCredentialsEndpoint, http.MethodPost)

	var frameDoc map[string]interface{}

	require.NoError(t, json.Unmarshal([]byte(sampleFrame), &frameDoc))

	t.Run("derive credentials - success without opts nonce", func(t *testing.T) {
		req := &DeriveCredentialRequest{
			Credential: json.RawMessage(requestVC),
			Frame:      frameDoc,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		var response DeriveCredentialResponse
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)

		// verify VC
		derived, err := verifiable.ParseCredential(response.VerifiableCredential,
			verifiable.WithPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(ops.vdr).PublicKeyFetcher(),
			),
			verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		)

		// check expected proof
		require.NoError(t, err)
		require.NotEmpty(t, derived)
		require.Len(t, derived.Proofs, 1)
		require.Equal(t, derived.Proofs[0]["type"], "BbsBlsSignatureProof2020")
		require.NotEmpty(t, derived.Proofs[0]["nonce"])
		require.NotEmpty(t, derived.Proofs[0]["proofValue"])
	})

	t.Run("derive credentials - success with empty nonce", func(t *testing.T) {
		nonce := ""
		req := &DeriveCredentialRequest{
			Credential: json.RawMessage(requestVC),
			Frame:      frameDoc,
			Opts:       DeriveCredentialOptions{Nonce: &nonce},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		var response DeriveCredentialResponse
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)

		// verify VC
		derived, err := verifiable.ParseCredential(response.VerifiableCredential,
			verifiable.WithPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(ops.vdr).PublicKeyFetcher(),
			),
			verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		)

		// check expected proof
		require.NoError(t, err)
		require.NotEmpty(t, derived)
		require.Len(t, derived.Proofs, 1)
		require.Equal(t, derived.Proofs[0]["type"], "BbsBlsSignatureProof2020")
		require.Empty(t, derived.Proofs[0]["nonce"])
		require.NotEmpty(t, derived.Proofs[0]["proofValue"])
	})

	t.Run("derive credentials - success with opts base64 nonce", func(t *testing.T) {
		nonce := "lEixQKDQvRecCifKl789TQj+Ii6YWDLSwn3AxR0VpPJ1QV5htod/0VCchVf1zVM0y2E="

		req := &DeriveCredentialRequest{
			Credential: json.RawMessage(requestVC),
			Frame:      frameDoc,
			Opts: DeriveCredentialOptions{
				Nonce: &nonce,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		var response DeriveCredentialResponse
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)

		// verify VC
		derived, err := verifiable.ParseCredential(response.VerifiableCredential,
			verifiable.WithPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(ops.vdr).PublicKeyFetcher(),
			),
			verifiable.WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		)

		// check expected proof
		require.NoError(t, err)
		require.NotEmpty(t, derived)
		require.Len(t, derived.Proofs, 1)
		require.Equal(t, derived.Proofs[0]["type"], "BbsBlsSignatureProof2020")
		require.NotEmpty(t, derived.Proofs[0]["nonce"])
		require.EqualValues(t, derived.Proofs[0]["nonce"], nonce)
		require.NotEmpty(t, derived.Proofs[0]["proofValue"])
	})

	t.Run("derive credentials  - invalid request", func(t *testing.T) {
		rr := serveHTTPMux(t, handler, endpoint, []byte("invalid json"), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), invalidRequestErrMsg)
	})

	t.Run("derive credentials  - invalid request empty credential", func(t *testing.T) {
		req := &DeriveCredentialRequest{}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "credential is mandatory")
	})

	t.Run("derive credentials  - invalid request empty frame", func(t *testing.T) {
		req := &DeriveCredentialRequest{
			Credential: json.RawMessage(vcForDerive),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "frame is mandatory")
	})

	t.Run("derive credentials  - failed to parse credential", func(t *testing.T) {
		req := &DeriveCredentialRequest{
			Credential: json.RawMessage(`{"k":"v"}`),
			Frame:      frameDoc,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse credential")
	})

	t.Run("derive credentials - failed to generate BBS selective disclosure", func(t *testing.T) {
		count := 0
		customOps, err := New(&Config{
			StoreProvider: ariesmemstorage.NewProvider(),
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					count++

					if count == 1 && didID == didKey {
						k := key.New()

						d, e := k.Read(didKey)
						if e != nil {
							return nil, e
						}

						return d, nil
					}
					return nil, fmt.Errorf("did not found")
				},
			},
			DocumentLoader: createTestDocumentLoader(t),
		})
		require.NoError(t, err)

		req := &DeriveCredentialRequest{
			Credential: json.RawMessage(requestVC),
			Frame:      frameDoc,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, getHandler(t, customOps, deriveCredentialsEndpoint, http.MethodPost),
			endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to generate BBS selective disclosure")
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

	loader := createTestDocumentLoader(t)

	op, err := New(&Config{
		StoreProvider:  ariesmemstorage.NewProvider(),
		KeyManager:     customKMS,
		Crypto:         customCrypto,
		DocumentLoader: loader,
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
			StoreProvider: ariesmemstorage.NewProvider(),
			KeyManager:    customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, signingKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
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
			StoreProvider: ariesmemstorage.NewProvider(),
			KeyManager:    customKMS2,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, signingKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
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
			StoreProvider:  ariesmemstorage.NewProvider(),
			Crypto:         customCrypto,
			KeyManager:     customKMS,
			DocumentLoader: loader,
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
			Crypto:         customCrypto,
			StoreProvider:  ariesmemstorage.NewProvider(),
			KeyManager:     customKMS,
			VDRI:           &vdrmock.MockVDRegistry{ResolveErr: errors.New("resolve error")},
			DocumentLoader: loader,
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
	t.Helper()

	return getHandlerWithError(t, op, lookupPath, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookupPath, methodToLookup string) Handler {
	t.Helper()

	return handlerLookup(t, op, lookupPath, methodToLookup)
}

func handlerLookup(t *testing.T, op *Operation, lookupPath, methodToLookup string) Handler {
	t.Helper()

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
	t.Helper()

	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
}

//nolint:unparam
func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder {
	t.Helper()

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
	t.Helper()

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

	p := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}

// nolint:gochecknoglobals // embedded test contexts
var (
	//go:embed testdata/citizenship-v1.jsonld
	citizenshipVocab []byte
	//go:embed testdata/examples-v1.jsonld
	examplesV1Vocab []byte
)

func createTestDocumentLoader(t *testing.T) *jld.DocumentLoader {
	t.Helper()

	loader, err := jld.NewDocumentLoader(ariesmockstorage.NewMockStoreProvider(),
		jld.WithExtraContexts(
			jld.ContextDocument{
				URL:         "https://w3id.org/citizenship/v1",
				DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
				Content:     citizenshipVocab,
			},
			jld.ContextDocument{
				URL:     "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
				Content: examplesV1Vocab,
			},
		),
	)
	require.NoError(t, err)

	return loader
}

// signVCWithBBS signs VC with bbs and returns did used for signing.
func signVCWithBBS(t *testing.T, vc *verifiable.Credential) string {
	t.Helper()

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)
	require.NotEmpty(t, privKey)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	methodID := fingerprint.KeyFingerprint(0xeb, pubKeyBytes)
	didKey := fmt.Sprintf("did:key:%s", methodID)
	keyID := fmt.Sprintf("%s#%s", didKey, methodID)

	bbsSigner, err := newBBSSigner(privKey)
	require.NoError(t, err)

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      keyID,
	}

	loader := createTestDocumentLoader(t)

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(loader))
	require.NoError(t, err)

	vcSignedBytes, err := json.Marshal(vc)
	require.NoError(t, err)
	require.NotEmpty(t, vcSignedBytes)

	vcVerified, err := verifiable.ParseCredential(vcSignedBytes,
		verifiable.WithEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
		verifiable.WithJSONLDDocumentLoader(loader),
	)
	require.NoError(t, err)
	require.NotNil(t, vcVerified)

	return didKey
}

type bbsSigner struct {
	privKeyBytes []byte
}

func newBBSSigner(privKey *bbs12381g2pub.PrivateKey) (*bbsSigner, error) { //nolint:interfacer
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privKeyBytes: privKeyBytes}, nil
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	msgs := s.textToLines(string(data))

	return bbs12381g2pub.New().Sign(msgs, s.privKeyBytes)
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}
