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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/tink/go/keyset"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
	didmethodoperation "github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"

	"github.com/trustbloc/edge-service/pkg/client/uniregistrar"
	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/mock/didbloc"
	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
	"github.com/trustbloc/edge-service/pkg/internal/mock/kms"
)

const (

	// json keys for compose issue credential options
	keyID   = "kid"
	purpose = "proofPurpose"
	created = "created"

	validContext = `"@context":["https://www.w3.org/2018/credentials/v1"]`

	testUUID = "4aae6b86-8e42-4d14-8cf5-21772ccb24aa"

	testURLQueryID = "http://test.com/" + testUUID

	testStoreCredentialRequest = `{
		"profile": "issuer",
		"credential" : "{\"@context\":\"https:\/\/www.w3.org\/2018\/credentials\/v1\",\"id\":\` +
		`"http:\/\/example.edu\/credentials\/1872\/` + testUUID + `\",\"type\":\` +
		`"VerifiableCredential\",\"credentialSubject\":{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"},` +
		`\"issuer\":{\"id\":\"did:example:76e12ec712ebc6f1c221ebfeb1f\",\"name\":\"Example University\"}` +
		`,\"issuanceDate\":\"2010-01-01T19:23:24Z\"}"
	}`

	testStoreCredentialRequestBadVC = `{
	   "profile":"issuer",
	   "credential":""
	}`

	testStoreIncorrectCredentialRequest = `{
		"profile": "",
		"credential" : "{\"@context\":\"https:\/\/www.w3.org\/2018\/credentials\/v1\",\"id\":\` +
		`"http:\/\/example.edu\/credentials\/1872\",\"type\":\"VerifiableCredential\",\"credentialSubject\":{\"id\` +
		`":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"},\"issuer\":{\"id\":\"did:example:76e12ec712ebc6f1c221ebfeb1f\` +
		`",\"name\":\"Example University\"},\"issuanceDate\":\"2010-01-01T19:23:24Z\"}"
	}`

	testIssuerProfile = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
        "didKeyType": "Ed25519"
	}`
	testIssuerProfileWithDisableVCStatus = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
		"disableVCStatus": true,
        "didKeyType": "Ed25519"
	}`
	testIssuerProfileWithDID = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
        "did": "did:peer:22",
        "didPrivateKey": "key",
        "didKeyID": "did1#key1"
	}`

	validVC = `{` +
		validContext + `,
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
	}`

	prCardVC = `{
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1"
	  ],
	  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	  "type": [
		"VerifiableCredential",
		"PermanentResidentCard"
	  ],
	  "name": "Permanent Resident Card",
	  "description": "Permanent Resident Card",
	  "issuer": "did:example:28394728934792387",
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
		"image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
		"residentSince": "2015-01-01",
		"lprCategory": "C09",
		"lprNumber": "999-999-999",
		"commuterClassification": "C1",
		"birthCountry": "Bahamas",
		"birthDate": "1958-07-17"
	  }
	}
	`

	validVCWithoutStatus = `{` +
		validContext + `,
	  "id": "http://example.edu/credentials/1872",
	  "type": "VerifiableCredential",
	  "credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	  },
	  "issuer": {
		"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		"name": "vc without status"
	  },
	  "issuanceDate": "2010-01-01T19:23:24Z"
	}`

	validVCWithProof = `{
	   "@context":[
		  "https://www.w3.org/2018/credentials/v1"
	   ],
	   "credentialSchema":[
	   ],
	   "credentialStatus":{
		  "id":"https://example.gov/status/24",
		  "type":"CredentialStatusList2017"
	   },
	   "credentialSubject":{
		  "id":"did:example:ebfeb1f712ebc6f1c276e12ec21"
	   },
	   "id":"http://example.edu/credentials/1872",
	   "issuanceDate":"2010-01-01T19:23:24Z",
	   "issuer":{
		  "id":"did:example:76e12ec712ebc6f1c221ebfeb1f",
		  "name":"Example University"
	   },
	   "proof":{
		  "created":"2020-03-23T17:20:15Z",
		  "jws":"eyJhbGciOiJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..` +
		`-M4JuuSvRurmWqX0S_x2eXg-ZaaDhkAUQ1GlV9DjD0WKZUKJefSkSgevYro64aFzQEa_gK7b1akJCB7XZtH1Aw",
		  "type":"Ed25519Signature2018",
		  "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiBpn9XWyJlGpny_` +
		`ViTH75fi43ThiIlGUyc1rQEb3VgreQ==#key-1"
	   },
	   "type":"VerifiableCredential"
	}`
	// VC without issuer
	invalidVC = `{` +
		validContext + `,
	  "id": "http://example.edu/credentials/1872",
	  "type": "VerifiableCredential",
	  "credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	  },
	  "issuanceDate": "2010-01-01T19:23:24Z"
	}`

	validVCStatus = `{
	  "@context": [
		"https://www.w3.org/2018/credentials/v1"
	  ],
	  "credentialSchema": [],
	  "credentialSubject": {
		"currentStatus": "Revoked",
		"statusReason": "Disciplinary action"
	  },
	  "id": "#ID",
	  "issuanceDate": "2020-02-18T17:55:31.1381994Z",
	  "issuer": {
		"id": "did:example:76e12ec712ebc6f1c221ebfeb12",
		"name": "Example University"
	  },
	  "type": "VerifiableCredential"
	}`

	testStructuredDocMessage1 = `"Hello World!"`

	testStructuredDocument1 = `{
	   "id":"someID",
	   "meta":{
		  "created":"2019-06-18"
	   },
	   "content":{
		  "message":` + testStructuredDocMessage1 + `
	   }
	}`

	testStructuredDocument2 = `{
	   "id":"someID",
	   "meta":{
		  "created":"2019-06-18"
	   },
	   "content":{
		  "message":"Howdy World!"
	   }
	}`

	validVP = `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1"
		],
		"id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		"type": "VerifiablePresentation",
		"verifiableCredential": [{
			"@context": [
				"https://www.w3.org/2018/credentials/v1",
				"https://www.w3.org/2018/credentials/examples/v1"
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
		"proof": {
			"type": "Ed25519Signature2018",
			"created": "2020-01-21T16:44:53+02:00",
			"proofValue": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01m` +
		`q-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVB` +
		`Ah4vGHSrQyHUGlcTwLtjPAnKb78"
		},
		"refreshService": {
			"id": "https://example.edu/refresh/3732",
			"type": "ManualRefreshService2018"
		}
	}`

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
				"https://www.w3.org/2018/credentials/examples/v1"
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
)

// errVaultNotFound throws an error when vault is not found
var errVaultNotFound = errors.New("vault not found")

// errDocumentNotFound throws an error when document associated with ID is not found
var errDocumentNotFound = errors.New("edv does not have a document associated with ID")

type mockProvider struct {
	numTimesCreateStoreCalledSuccessfully   int
	numTimesCreateStoreIsCallableWithoutErr int
	createStoreErr                          error
	store                                   storage.Store
}

func (m *mockProvider) CreateStore(_ string) error {
	if m.numTimesCreateStoreIsCallableWithoutErr == m.numTimesCreateStoreCalledSuccessfully {
		return m.createStoreErr
	}

	m.numTimesCreateStoreCalledSuccessfully++

	return nil
}

func (m *mockProvider) OpenStore(name string) (storage.Store, error) {
	return m.store, nil
}

func (m *mockProvider) CloseStore(name string) error {
	panic("implement me")
}

func (m *mockProvider) Close() error {
	panic("implement me")
}

func TestNew(t *testing.T) {
	t.Run("test error from opening credential store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		op, err := New(&Config{StoreProvider: &mockstore.Provider{ErrOpenStoreHandle: fmt.Errorf("error open store")},
			EDVClient: client, VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, op)
	})
	t.Run("fail to create credential store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		op, err := New(&Config{StoreProvider: &mockstore.Provider{
			ErrCreateStore: fmt.Errorf("create error")}, EDVClient: client, VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create error")
		require.Nil(t, op)
	})
	t.Run("test error from csl", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		op, err := New(&Config{StoreProvider: &mockstore.Provider{FailNameSpace: "credentialstatus"},
			EDVClient: client, VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to instantiate new csl status")
		require.Nil(t, op)
	})
	t.Run("fail to prepare JWE crypto", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		testCreateStoreErr := errors.New("test create store error")

		op, err := New(&Config{
			StoreProvider: &mockProvider{numTimesCreateStoreIsCallableWithoutErr: 2,
				createStoreErr: testCreateStoreErr},
			KMSSecretsProvider: mem.NewProvider(),
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{},
			VDRI:               &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.Equal(t, testCreateStoreErr, err)
		require.Nil(t, op)
	})
	t.Run("fail to prepare MAC crypto", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
		testCreateStoreErr := errors.New("test create store error")

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			StoreProvider: &mockProvider{store: &mockstore.MockStore{Store: make(map[string][]byte)},
				numTimesCreateStoreIsCallableWithoutErr: 3,
				createStoreErr:                          testCreateStoreErr},
			KMSSecretsProvider: mem.NewProvider(),
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.Equal(t, testCreateStoreErr, err)
		require.Nil(t, op)
	})
}

func TestUpdateCredentialStatusHandler(t *testing.T) {
	const (
		issuerMode   = "issuer"
		combinedMode = "combined"
	)

	testUpdateCredentialStatusHandler(t, issuerMode)
	testUpdateCredentialStatusHandler(t, combinedMode)
}

func testUpdateCredentialStatusHandler(t *testing.T, mode string) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
	s := make(map[string][]byte)
	s["profile_"+issuerMode+"_Example University"] = []byte(testIssuerProfile)
	s["profile_"+issuerMode+"_vc without status"] = []byte(testIssuerProfileWithDisableVCStatus)

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{StoreProvider: &mockstore.Provider{Store: &mockstore.MockStore{Store: s}},
		KMSSecretsProvider: mem.NewProvider(), EDVClient: client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
		Crypto: &cryptomock.Crypto{},
		VDRI:   &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
	require.NoError(t, err)

	op.vcStatusManager = &mockVCStatusManager{getCSLValue: &cslstatus.CSL{}}

	updateCredentialStatusHandler := getHandler(t, op, updateCredentialStatusEndpoint, mode)

	t.Run("update credential status success", func(t *testing.T) {
		ucsReq := UpdateCredentialStatusRequest{Credential: validVC, Status: "revoked"}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, updateCredentialStatusEndpoint, bytes.NewBuffer(ucsReqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		updateCredentialStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test disable vc status", func(t *testing.T) {
		ucsReq := UpdateCredentialStatusRequest{Credential: validVCWithoutStatus, Status: "revoked"}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, updateCredentialStatusEndpoint, bytes.NewBuffer(ucsReqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		updateCredentialStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Contains(t, rr.Body.String(), "vc status is disabled for profile")
	})

	t.Run("test error decode request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, updateCredentialStatusEndpoint, bytes.NewBuffer([]byte("w")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		updateCredentialStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Contains(t, rr.Body.String(), "failed to decode request received")
	})

	t.Run("test error from parse credential", func(t *testing.T) {
		ucsReq := UpdateCredentialStatusRequest{Credential: invalidVC, Status: "revoked"}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, updateCredentialStatusEndpoint, bytes.NewBuffer(ucsReqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		updateCredentialStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Contains(t, rr.Body.String(), "unable to unmarshal the VC")
	})

	t.Run("test error from get profile", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: &mockstore.Provider{
			Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
			KMSSecretsProvider: mem.NewProvider(),
			EDVClient:          edv.NewMockEDVClient("test", nil, nil, []string{"testID"}),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			Crypto:             &cryptomock.Crypto{}, VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)
		op.vcStatusManager = &mockVCStatusManager{getCSLValue: &cslstatus.CSL{}}
		updateCredentialStatusHandler := getHandler(t, op, updateCredentialStatusEndpoint, mode)

		ucsReq := UpdateCredentialStatusRequest{Credential: validVC, Status: "revoked"}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, updateCredentialStatusEndpoint, bytes.NewBuffer(ucsReqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		updateCredentialStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Contains(t, rr.Body.String(), "failed to get profile")
	})

	t.Run("test error from update vc status", func(t *testing.T) {
		s := make(map[string][]byte)
		s["profile_"+issuerMode+"_Example University"] = []byte(testIssuerProfile)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: &mockstore.Provider{Store: &mockstore.MockStore{Store: s}},
			KMSSecretsProvider: mem.NewProvider(),
			EDVClient:          edv.NewMockEDVClient("test", nil, nil, []string{"testID"}),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			Crypto:             &cryptomock.Crypto{}, VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)
		op.vcStatusManager = &mockVCStatusManager{updateVCStatusErr: fmt.Errorf("error update vc status")}
		updateCredentialStatusHandler := getHandler(t, op, updateCredentialStatusEndpoint, mode)

		ucsReq := UpdateCredentialStatusRequest{Credential: validVC, Status: "revoked"}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, updateCredentialStatusEndpoint, bytes.NewBuffer(ucsReqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		updateCredentialStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Contains(t, rr.Body.String(), "failed to update vc status")
	})
}

func TestCreateProfileHandler(t *testing.T) {
	const (
		issuerMode   = "issuer"
		combinedMode = "combined"
	)

	testCreateProfileHandler(t, issuerMode)
	testCreateProfileHandler(t, combinedMode)
}

func testCreateProfileHandler(t *testing.T, mode string) {
	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		EDVClient:          client,
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
		Crypto:             &cryptomock.Crypto{},
		HostURL:            "localhost:8080", Domain: "testnet"})
	require.NoError(t, err)

	op.didBlocClient = &didbloc.Client{CreateDIDValue: createDefaultDID()}

	createProfileHandler := getHandler(t, op, createProfileEndpoint, mode)

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	t.Run("create profile success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		profile := vcprofile.DataProfile{}

		err = json.Unmarshal(rr.Body.Bytes(), &profile)

		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.Name)
		require.Contains(t, profile.URI, "https://example.com/credentials")
	})

	t.Run("create profile success - P256 key", func(t *testing.T) {
		profileReq := ProfileRequest{
			Name:          "issuer",
			URI:           "https://example.com/credentials",
			SignatureType: vccrypto.JSONWebSignature2020,
			DIDKeyType:    "P256",
		}

		reqBytes, err := json.Marshal(profileReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)

		profile := vcprofile.DataProfile{}
		err = json.Unmarshal(rr.Body.Bytes(), &profile)
		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.Name)
		require.Contains(t, profile.URI, "https://example.com/credentials")
	})

	t.Run("create profile - invalid key type", func(t *testing.T) {
		profileReq := ProfileRequest{
			Name:          "issuer",
			URI:           "https://example.com/credentials",
			SignatureType: vccrypto.JSONWebSignature2020,
			DIDKeyType:    "invalid",
		}

		reqBytes, err := json.Marshal(profileReq)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(),
			"no key found to match key type:invalid and signature type:JsonWebSignature2020")
	})

	t.Run("create profile success with uni Registrar config", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{ID: "did1",
				Authentication: []did.VerificationMethod{{PublicKey: did.PublicKey{ID: "did1#key-1"}}}}},
			HostURL: "localhost:8080"})

		require.NoError(t, err)

		op.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDValue: "did1", CreateDIDKeys: []didmethodoperation.Key{{
			ID: "did1#key-1"}, {ID: "did1#key2"}}}

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)

		reqBytes, err := json.Marshal(ProfileRequest{Name: "profile",
			URI: "https://example.com/credentials", SignatureType: "Ed25519Signature2018", DIDKeyType: vccrypto.Ed25519KeyType,
			UNIRegistrar: UNIRegistrar{DriverURL: "driverURL"}})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer(reqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		profile := vcprofile.DataProfile{}

		err = json.Unmarshal(rr.Body.Bytes(), &profile)
		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.Name)
		require.Contains(t, profile.URI, "https://example.com/credentials")
		require.Equal(t, "did1#key-1", profile.Creator)
	})

	t.Run("create profile error with uni Registrar config", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{ID: "did1",
				Authentication: []did.VerificationMethod{{PublicKey: did.PublicKey{ID: "did1#key1"}}}}},
			HostURL: "localhost:8080"})

		require.NoError(t, err)

		op.uniRegistrarClient = &mockUNIRegistrarClient{CreateDIDErr: fmt.Errorf("create did error")}

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)

		reqBytes, err := json.Marshal(ProfileRequest{Name: "profile",
			URI: "https://example.com/credentials", SignatureType: "Ed25519Signature2018", DIDKeyType: vccrypto.Ed25519KeyType,
			UNIRegistrar: UNIRegistrar{DriverURL: "driverURL"}})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer(reqBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did doc from uni-registrar")
	})

	t.Run("create profile success without creating did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{ID: "did1",
				Authentication: []did.VerificationMethod{{PublicKey: did.PublicKey{ID: "did1#key1"}}}}},
			HostURL: "localhost:8080"})

		require.NoError(t, err)

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfileWithDID)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		profile := vcprofile.DataProfile{}

		err = json.Unmarshal(rr.Body.Bytes(), &profile)
		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.Name)
		require.Contains(t, profile.URI, "https://example.com/credentials")
		require.Equal(t, "did1#key1", profile.Creator)
	})

	t.Run("test failed to resolve did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI:    &vdrimock.MockVDRIRegistry{ResolveErr: fmt.Errorf("resolve error")},
			HostURL: "localhost:8080"})

		require.NoError(t, err)

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfileWithDID)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to resolve did")
	})

	t.Run("missing profile name", func(t *testing.T) {
		prBytes, err := json.Marshal(ProfileRequest{})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer(prBytes))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errResp.Message, "missing profile name")
	})
	t.Run("create profile error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, invalidRequestErrMsg+": EOF", errResp.Message)
	})
	t.Run("create profile error unable to write a response while reading the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createProfileHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Unable to send error message, response writer failed")
	})
	t.Run("create profile error while saving the profile", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		op.didBlocClient = &didbloc.Client{CreateDIDValue: createDefaultDID()}
		op.profileStore = vcprofile.New(&mockStore{
			get: func(s string) (bytes []byte, e error) {
				return nil, storage.ErrValueNotFound
			},
			put: func(s string, bytes []byte) error {
				return errors.New("db error while saving profile")
			}})

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "db error while saving profile")
	})

	t.Run("create profile error while creating did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client, KeyManager: &kms.KeyManager{CreateKeyValue: kh},
			VDRI:    &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		op.didBlocClient = &didbloc.Client{CreateDIDErr: fmt.Errorf("create did error")}
		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "create did error")
	})
}

func TestGetProfileHandler(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		Crypto:             &cryptomock.Crypto{},
		EDVClient:          client,
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
		HostURL:            "localhost:8080"})

	require.NoError(t, err)

	op.didBlocClient = &didbloc.Client{CreateDIDValue: createDefaultDID()}

	getProfileHandler := getHandler(t, op, getProfileEndpoint, "issuer")

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	notFoundID := "test"
	req, err := http.NewRequest(http.MethodGet,
		"/profile/"+notFoundID,
		bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars["id"] = notFoundID

	req = mux.SetURLVars(req, urlVars)

	t.Run("get profile success", func(t *testing.T) {
		profile := createProfileSuccess(t, op)

		r, err := http.NewRequest(http.MethodGet,
			"/profile/"+profile.Name,
			bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars["id"] = profile.Name
		req = mux.SetURLVars(r, urlVars)

		getProfileHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		profileResponse := &vcprofile.DataProfile{}
		err = json.Unmarshal(rr.Body.Bytes(), profileResponse)
		require.NoError(t, err)
		require.Equal(t, profileResponse.Name, profile.Name)
		require.Equal(t, profileResponse.URI, profile.URI)
	})
	t.Run("get profile error, bad request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet,
			"/profile/"+notFoundID,
			bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		getProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func createProfileSuccess(t *testing.T, op *Operation) *vcprofile.DataProfile {
	req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createProfileEndpoint := getHandler(t, op, createProfileEndpoint, "issuer")
	createProfileEndpoint.Handle().ServeHTTP(rr, req)

	profile := &vcprofile.DataProfile{}

	err = json.Unmarshal(rr.Body.Bytes(), &profile)
	require.NoError(t, err)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.NotEmpty(t, profile.Name)

	return profile
}

type failingCrypto struct {
}

func (m failingCrypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	panic("implement me")
}

func (m failingCrypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (m failingCrypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (m failingCrypto) Verify(signature, msg []byte, kh interface{}) error {
	panic("implement me")
}

func (m failingCrypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	return nil, errors.New("i always fail")
}

func (m failingCrypto) VerifyMAC(_, data []byte, kh interface{}) error {
	panic("implement me")
}

type failingJWEEncrypt struct {
	encryptReturnValue *jose.JSONWebEncryption
	errEncrypt         error
}

func (f *failingJWEEncrypt) Encrypt(_, _ []byte) (*jose.JSONWebEncryption, error) {
	return f.encryptReturnValue, f.errEncrypt
}

func TestStoreVCHandler(t *testing.T) {
	t.Run("store vc success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("store vc err while creating the document - vault not found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errResp.Message, errVaultNotFound.Error())
	})
	t.Run("store vc err missing profile name", func(t *testing.T) {
		client := NewMockEDVClient("test")

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreIncorrectCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errResp.Message, "missing profile name")
	})
	t.Run("store vc err unable to unmarshal vc", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequestBadVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, "unable to unmarshal the VC: decode new credential: "+
			"embedded proof is not JSON: unexpected end of JSON input", errResp.Message)
	})
	t.Run("store vc err while computing MAC", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})

		op.macCrypto = failingCrypto{}
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		require.Equal(t, "i always fail", errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("store vc err while encrypting structured doc", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})

		testError := errors.New("test encryption failure")

		op.jweEncrypter = &failingJWEEncrypt{errEncrypt: testError}

		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		require.Equal(t, testError.Error(), errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("store vc err while serializing JWE", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})

		op.jweEncrypter = &failingJWEEncrypt{encryptReturnValue: &jose.JSONWebEncryption{}}

		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		require.Equal(t, "ciphertext cannot be empty", errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestRetrieveVCHandler(t *testing.T) {
	t.Run("retrieve vc success", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, testStructuredDocMessage1, rr.Body.String())
	})
	t.Run("retrieve vc success - multiple VCs "+
		"found under the same ID but they have identical contents", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID1", "testID2"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, testStructuredDocMessage1, rr.Body.String())
	})
	t.Run("retrieve vc error - multiple VCs "+
		"found under the same ID and they have differing contents", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID1", "testID2"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument2)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)

		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errMultipleInconsistentVCsFoundForOneID.Error(), errResp.Message)

		require.Equal(t, http.StatusConflict, rr.Code)
	})
	t.Run("retrieve vc fail - no VC found under the given ID", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil, nil, nil)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, `no VC under profile "test" was found with the given id`, errResp.Message)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("retrieve vc error when missing profile name", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile name")
	})
	t.Run("retrieve vc error when missing vc ID", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		q := req.URL.Query()
		q.Add("profile", getTestProfile().Name)
		req.URL.RawQuery = q.Encode()
		op.retrieveCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing verifiable credential ID")
	})
	t.Run("retrieve vc error when no document is found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			EDVClient:          client,
			Crypto:             &cryptomock.Crypto{},
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := req.URL.Query()
		q.Add("id", testUUID)
		q.Add("profile", getTestProfile().Name)
		req.URL.RawQuery = q.Encode()

		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), errDocumentNotFound.Error())
	})
	t.Run("retrieve vc fail when writing document retrieval success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		var logContents bytes.Buffer
		log.SetOutput(&logContents)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1)

		retrieveVCHandler := getHandler(t, op, retrieveCredentialEndpoint, "issuer")

		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := req.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		req.URL.RawQuery = q.Encode()

		rw := mockResponseWriter{}
		retrieveVCHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Failed to write response for document retrieval success: response writer failed")
	})
	t.Run("fail to compute MAC when querying vault", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		op.macCrypto = failingCrypto{}

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, `i always fail`,
			errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("fail to deserialize JWE", func(t *testing.T) {
		client := edv.NewMockEDVClient("test",
			&models.EncryptedDocument{JWE: []byte("{ not valid JWE }")},
			nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		errResp := &ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, "invalid character 'n' looking for beginning of object key string", errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestVCStatus(t *testing.T) {
	const mode = "issuer"

	t.Run("test error from get CSL", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			EDVClient:          client,
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{getCSLErr: fmt.Errorf("error get csl")}

		vcStatusHandler := getHandler(t, op, credentialStatusEndpoint, mode)

		req, err := http.NewRequest(http.MethodGet, credentialStatus+"/1", nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		vcStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "error get csl")
	})

	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"})

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			EDVClient:          client,
			Crypto:             &cryptomock.Crypto{},
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
			HostURL:            "localhost:8080"})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{
			getCSLValue: &cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{}}}

		vcStatusHandler := getHandler(t, op, credentialStatusEndpoint, mode)

		req, err := http.NewRequest(http.MethodGet, credentialStatus+"/1", nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		vcStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var csl cslstatus.CSL
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &csl))
		require.Equal(t, "https://example.gov/status/24", csl.ID)
	})
}

func TestOperation_validateProfileRequest(t *testing.T) {
	t.Run("valid profile ", func(t *testing.T) {
		profile := getProfileRequest()
		err := validateProfileRequest(profile)
		require.NoError(t, err)
	})
	t.Run("missing profile name", func(t *testing.T) {
		profile := getProfileRequest()
		profile.Name = ""
		err := validateProfileRequest(profile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing profile name")
	})
	t.Run("missing URI ", func(t *testing.T) {
		profile := getProfileRequest()
		profile.URI = ""
		err := validateProfileRequest(profile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing URI information")
	})
	t.Run("missing signature type ", func(t *testing.T) {
		profile := getProfileRequest()
		profile.SignatureType = ""
		err := validateProfileRequest(profile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signature type")
	})
	t.Run("parse uri failed", func(t *testing.T) {
		profile := getProfileRequest()
		profile.URI = "//not-valid.&&%^)$"
		err := validateProfileRequest(profile)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid uri")
	})
}

func TestOperation_GetRESTHandlers(t *testing.T) {
	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		Crypto:             &cryptomock.Crypto{},
		EDVClient:          edv.NewMockEDVClient("test", nil, nil, []string{"testID"}),
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
		HostURL:            "localhost:8080"})

	require.NoError(t, err)

	t.Run("invalid mode", func(t *testing.T) {
		_, err := op.GetRESTHandlers("invalid")
		require.Error(t, err)
	})
	t.Run("issuer mode", func(t *testing.T) {
		handlers, err := op.GetRESTHandlers("issuer")
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
	})
	t.Run("verifier mode", func(t *testing.T) {
		handlers, err := op.GetRESTHandlers("verifier")
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
	})
}

func TestIssueCredential(t *testing.T) {
	endpoint := "/test/credentials/issueCredential"
	keyID := "key-1"
	issuerProfileDIDKey := "did:test:abc#" + keyID
	profile := getTestProfile()
	profile.Creator = issuerProfileDIDKey

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyID: keyID, CreateKeyValue: kh},
		Crypto:             &cryptomock.Crypto{},
		VDRI: &vdrimock.MockVDRIRegistry{
			ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (*did.Doc, error) {
				return createDIDDocWithKeyID(didID, keyID, pubKey), nil
			}},
	})
	require.NoError(t, err)

	err = op.profileStore.SaveProfile(profile)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = profile.Name

	handler := getHandler(t, op, issueCredentialPath, issuerMode)

	t.Run("issue credential - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		closeableKMS := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyID: keyID, CreateKeyValue: keyHandle},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDocWithKeyID(didID, keyID, base58.Decode(signingKey)), nil
				},
			},
			Crypto: &cryptomock.Crypto{},
		})
		require.NoError(t, err)

		profile.SignatureRepresentation = verifiable.SignatureJWS
		profile.SignatureType = vccrypto.JSONWebSignature2020

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, issuerMode)

		const createdTime = "2011-04-16T18:11:09-04:00"
		ct, err := time.Parse(time.RFC3339, createdTime)
		require.NoError(t, err)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts: &IssueCredentialOptions{
				AssertionMethod:    "did:local:abc#" + keyID,
				VerificationMethod: "did:local:abc#" + keyID,
				Created:            &ct,
				Challenge:          challenge,
				Domain:             domain,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVCResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok := signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, cslstatus.Context, signedVCResp["@context"].([]interface{})[1])
		require.Equal(t, jsonWebSignature2020Context, signedVCResp["@context"].([]interface{})[2])
		require.Equal(t, vccrypto.JSONWebSignature2020, proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:local:abc#"+keyID, proof["verificationMethod"])
		require.Equal(t, "assertionMethod", proof["proofPurpose"])
		require.Equal(t, createdTime, proof["created"])
		require.Equal(t, challenge, proof[challenge])
		require.Equal(t, domain, proof[domain])

		// default - DID from the issuer profile
		req.Opts.VerificationMethod = ""

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVCResp = make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok = signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, vccrypto.JSONWebSignature2020, proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:local:abc#"+keyID, proof["verificationMethod"])
		require.Equal(t, "assertionMethod", proof["proofPurpose"])

		// default - DID from the issuer profile
		req.Opts.AssertionMethod = ""
		req.Opts.VerificationMethod = ""

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVCResp = make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])
		require.NotEmpty(t, signedVCResp["credentialStatus"])

		proof, ok = signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, vccrypto.JSONWebSignature2020, proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, issuerProfileDIDKey, proof["verificationMethod"])
		require.Equal(t, "assertionMethod", proof["proofPurpose"])
	})

	t.Run("issue credential with opts - success", func(t *testing.T) {
		customVerificationMethod := "did:test:zzz#" + keyID

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		closeableKMS := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: keyHandle},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDocWithKeyID(didID, keyID, base58.Decode(signingKey)), nil
				},
			},
			Crypto: &cryptomock.Crypto{},
		})
		require.NoError(t, err)

		profile.SignatureRepresentation = verifiable.SignatureJWS
		profile.SignatureType = vccrypto.Ed25519Signature2018

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts: &IssueCredentialOptions{
				AssertionMethod: customVerificationMethod,
				ProofPurpose:    assertionMethod,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		signedVCResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok := signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, 2, len(signedVCResp["@context"].([]interface{})))
		require.Equal(t, vccrypto.Ed25519Signature2018, proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, customVerificationMethod, proof["verificationMethod"])
		require.Equal(t, assertionMethod, proof["proofPurpose"])
	})

	t.Run("issue credential with opts - invalid proof purpose", func(t *testing.T) {
		customPurpose := "customPurpose"

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		closeableKMS := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: keyHandle},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDoc(didID, base58.Decode(signingKey)), nil
				},
			},
			Crypto: &cryptomock.Crypto{},
		})
		require.NoError(t, err)

		profile.SignatureRepresentation = verifiable.SignatureJWS

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts: &IssueCredentialOptions{
				ProofPurpose: customPurpose,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid proof option : customPurpose")
	})

	t.Run("issue credential - invalid profile", func(t *testing.T) {
		keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: keyHandle},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, issuerMode)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid issuer profile")
	})

	t.Run("issue credential - invalid request", func(t *testing.T) {
		rr := serveHTTPMux(t, handler, endpoint, []byte("invalid json"), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), invalidRequestErrMsg)
	})

	t.Run("issue credential - invalid vc", func(t *testing.T) {
		req := &IssueCredentialRequest{
			Credential: []byte(invalidVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate credential")
	})

	t.Run("issue credential - invalid vc", func(t *testing.T) {
		req := &IssueCredentialRequest{
			Credential: []byte(invalidVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate credential")
	})

	t.Run("issue credential - issuer ID validation", func(t *testing.T) {
		vc, err := verifiable.NewUnverifiedCredential([]byte(validVC))
		require.NoError(t, err)

		vc.Issuer.ID = "invalid did"

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		req := &IssueCredentialRequest{
			Credential: vcBytes,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "issuer.id: Does not match format 'uri'")

		// valid URI
		vc.Issuer.ID = "http://example.com/issuer"

		vcBytes, err = vc.MarshalJSON()
		require.NoError(t, err)

		req = &IssueCredentialRequest{
			Credential: vcBytes,
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)
	})

	t.Run("issue credential - DID not resolvable", func(t *testing.T) {
		keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op1, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: keyHandle},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (*did.Doc, error) {
					return nil, errors.New("did not found")
				}},
		})
		require.NoError(t, err)

		issueHandler := getHandler(t, op1, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y#key-1"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "does not have a value associated with this key")
	})

	t.Run("issue credential - add credential status error", func(t *testing.T) {
		closeableKMS := &kmsmock.CloseableKMS{SignMessageErr: fmt.Errorf("error sign msg")}
		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", base58.Decode(signingKey))

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		op.vcStatusManager = &mockCredentialStatusManager{CreateErr: errors.New("csl error")}

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to add credential status: csl error")
	})

	t.Run("issue credential - invalid assertion", func(t *testing.T) {
		closeableKMS := &kmsmock.CloseableKMS{SignMessageErr: fmt.Errorf("error sign msg")}
		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", base58.Decode(signingKey))

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid assertion method : [did:test:urosdjwas7823y]")
	})

	t.Run("issue credential - signing error", func(t *testing.T) {
		closeableKMS := &kmsmock.CloseableKMS{}
		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", base58.Decode(signingKey))

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign credential")},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y#key-1"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign credential")
	})
}

func TestComposeAndIssueCredential(t *testing.T) {
	type TermsOfUse struct {
		ID   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	}

	// vc compose request values
	name := "John Doe"
	customField := "customField"
	customFieldVal := "customFieldVal"
	subject := "did:example:oleh394sqwnlk223823ln"
	issuer := "did:example:823jhkasjou0923bkajsdd"
	issueDate := time.Now().UTC()
	expiryDate := issueDate.AddDate(0, 3, 0).UTC()
	termsOfUseID := "http://example.com/policies/credential/4"
	termsOfUseType := "IssuerPolicy"
	degreeType := "UniversityDegree"
	types := []string{degreeType}
	evidenceID := "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231"
	evidenceVerifier := "https://example.edu/issuers/14"
	key1ID := "key-22"

	termsOfUseJSON, err := json.Marshal(&TermsOfUse{
		ID:   termsOfUseID,
		Type: termsOfUseType,
	})
	require.NoError(t, err)

	claim := make(map[string]interface{})
	claim["name"] = name
	claim[customField] = customFieldVal

	evidence := make(map[string]interface{})
	evidence["id"] = evidenceID
	evidence["verifier"] = evidenceVerifier
	evidence[customField] = customFieldVal

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
		Crypto:             &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign credential")},
	})
	require.NoError(t, err)

	handler := getHandler(t, op, composeAndIssueCredentialPath, issuerMode)

	endpoint := "/test/credentials/composeAndIssueCredential"
	issuerProfileDIDKey := "did:test:abc#" + key1ID
	profile := getTestProfile()
	profile.Creator = issuerProfileDIDKey

	err = op.profileStore.SaveProfile(profile)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = profile.Name

	t.Run("compose and issue credential - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		closeableKMS := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", base58.Decode(signingKey))

		op, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
				return createDIDDocWithKeyID(didID, key1ID, base58.Decode(signingKey)), nil
			}},
			Crypto: &cryptomock.Crypto{},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		restHandler := getHandler(t, op, composeAndIssueCredentialPath, issuerMode)

		claimJSON, err := json.Marshal(claim)
		require.NoError(t, err)

		evidenceJSON, err := json.Marshal(evidence)
		require.NoError(t, err)

		// test - create compose request with all the fields
		req := &ComposeCredentialRequest{
			Issuer:         issuer,
			Subject:        subject,
			IssuanceDate:   &issueDate,
			ExpirationDate: &expiryDate,
			Types:          types,
			Claims:         claimJSON,
			TermsOfUse:     termsOfUseJSON,
			Evidence:       evidenceJSON,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTPMux(t, restHandler, endpoint, reqBytes, urlVars)
		require.Equal(t, http.StatusCreated, rr.Code)

		// validate the response
		vcResp, err := verifiable.NewUnverifiedCredential(rr.Body.Bytes())
		require.NoError(t, err)

		// top level values
		require.Equal(t, issuer, vcResp.Issuer.ID)
		require.Equal(t, 1, len(vcResp.Types))
		require.Equal(t, degreeType, vcResp.Types[0])
		require.Equal(t, &issueDate, vcResp.Issued)
		require.Equal(t, &expiryDate, vcResp.Expired)
		require.NotNil(t, vcResp.Evidence)
		require.NotNil(t, issuer, vcResp.Issuer)

		// credential subject
		credSubject, ok := vcResp.Subject.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, subject, credSubject["id"])
		require.Equal(t, name, credSubject["name"])
		require.Equal(t, customFieldVal, credSubject[customField])

		// terms of use
		require.Equal(t, 1, len(vcResp.TermsOfUse))
		require.Equal(t, termsOfUseID, vcResp.TermsOfUse[0].ID)
		require.Equal(t, termsOfUseType, vcResp.TermsOfUse[0].Type)

		// evidence
		evidence, ok := vcResp.Evidence.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, evidenceID, evidence["id"])
		require.Equal(t, evidenceVerifier, evidence["verifier"])
		require.Equal(t, customFieldVal, evidence[customField])

		// test - create compose request without fields which has default value
		req.Types = nil
		req.Claims = nil
		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr = serveHTTPMux(t, restHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusCreated, rr.Code)

		// validate the response
		vcResp, err = verifiable.NewUnverifiedCredential(rr.Body.Bytes())
		require.NoError(t, err)
		require.Equal(t, 1, len(vcResp.Types))
		require.Equal(t, "VerifiableCredential", vcResp.Types[0])

		credSubject, ok = vcResp.Subject.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, subject, credSubject["id"])

		// test - with proof format, purpose & created
		const createdTime = "2011-04-16T18:11:09-04:00"
		proofFormatOptions := make(map[string]interface{})
		proofFormatOptions[keyID] = "did:test:hd9712akdsaishda7#" + key1ID
		proofFormatOptions[purpose] = "authentication"
		proofFormatOptions[created] = createdTime

		proofFormatOptionsJSON, err := json.Marshal(proofFormatOptions)
		require.NoError(t, err)

		req.Issuer = "different-did"
		req.ProofFormat = "jws"
		req.ProofFormatOptions = proofFormatOptionsJSON
		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, restHandler, endpoint, reqBytes, urlVars)
		require.Equal(t, http.StatusCreated, rr.Code)

		signedVCResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])
		require.NotEmpty(t, signedVCResp["credentialStatus"])

		proof, ok := signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:test:hd9712akdsaishda7#"+key1ID, proof["verificationMethod"])
		require.Equal(t, "authentication", proof["proofPurpose"])
		require.Equal(t, createdTime, proof["created"])
	})

	t.Run("compose and issue credential - invalid profile", func(t *testing.T) {
		ops, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		})
		require.NoError(t, err)

		restHandler := getHandler(t, ops, composeAndIssueCredentialPath, issuerMode)

		rr := serveHTTPMux(t, restHandler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid issuer profile")
	})

	t.Run("compose and issue credential - invalid request", func(t *testing.T) {
		rr := serveHTTPMux(t, handler, endpoint, []byte("invalid input"), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("compose and issue credential - add credential status error", func(t *testing.T) {
		ops, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		})
		require.NoError(t, err)

		ops.vcStatusManager = &mockCredentialStatusManager{CreateErr: errors.New("csl error")}

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		req := &ComposeCredentialRequest{}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		restHandler := getHandler(t, ops, composeAndIssueCredentialPath, issuerMode)

		// invoke the endpoint
		rr := serveHTTPMux(t, restHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to add credential status: csl error")
	})

	t.Run("compose and issue credential - signing failure", func(t *testing.T) {
		req := &ComposeCredentialRequest{}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign credential")
	})

	t.Run("compose and issue credential - build credential error (termsOfUse)", func(t *testing.T) {
		req := `{
			"termsOfUse":"should be object or array"
		}`

		// invoke the endpoint
		rr := serveHTTPMux(t, handler, endpoint, []byte(req), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to build credential")
	})

	t.Run("compose and issue credential - build credential error (claims)", func(t *testing.T) {
		req := `{
			"claims":"invalid"
		}`

		// invoke the endpoint
		rr := serveHTTPMux(t, handler, endpoint, []byte(req), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to build credential")
	})

	t.Run("compose and issue credential - build credential error (evidence)", func(t *testing.T) {
		req := `{
			"evidence":"invalid"
		}`

		// invoke the endpoint
		rr := serveHTTPMux(t, handler, endpoint, []byte(req), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to build credential")
	})

	t.Run("compose and issue credential - invalid proof format option", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		req := &ComposeCredentialRequest{
			ProofFormat:        "invalid-proof-format-value",
			ProofFormatOptions: []byte(fmt.Sprintf(`{"kid":"did:local:abc#%s"}`, key1ID)),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		op1, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (*did.Doc, error) {
					return createDIDDocWithKeyID(didID, key1ID, pubKey), nil
				}},
		})
		require.NoError(t, err)

		err = op1.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		handler1 := getHandler(t, op1, composeAndIssueCredentialPath, issuerMode)

		// invoke the endpoint
		rr := serveHTTPMux(t, handler1, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid proof format : invalid-proof-format-value")
	})

	t.Run("compose and issue credential - get signing DID error - invalid kid type", func(t *testing.T) {
		proofFormatOptions := 33

		proofFormatOptionsJSON, err := json.Marshal(proofFormatOptions)
		require.NoError(t, err)

		req := &ComposeCredentialRequest{
			ProofFormatOptions: proofFormatOptionsJSON,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to prepare signing options")
	})

	t.Run("compose and issue credential - get signing DID error - invalid kid type", func(t *testing.T) {
		proofFormatOptions := make(map[string]interface{})
		proofFormatOptions[keyID] = 23

		proofFormatOptionsJSON, err := json.Marshal(proofFormatOptions)
		require.NoError(t, err)

		req := &ComposeCredentialRequest{
			ProofFormatOptions: proofFormatOptionsJSON,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to prepare signing options: failed to prepare signing opts:")
	})
}

func TestGetComposeSigningOpts(t *testing.T) {
	t.Run("get signing opts", func(t *testing.T) {
		tests := []struct {
			name               string
			ProofFormatOptions string
			ProofFormat        string
			err                string
		}{
			{
				name:               "compose signing opts kid",
				ProofFormat:        ``,
				ProofFormatOptions: `{"kid":"kid1"}`,
			},
			{
				name:               "compose signing opts kid & purpose",
				ProofFormat:        `jws`,
				ProofFormatOptions: `{"kid":"kid1", "proofPurpose":"authentication"}`,
			},
			{
				name:        "compose signing opts kid, purpose & created",
				ProofFormat: `proofValue`,
				ProofFormatOptions: `{"kid":"kid1", "proofPurpose":"authentication",
							"created":"2019-04-16T18:11:09-04:00"}`,
			},
			{
				name:        "invalid signing opts",
				ProofFormat: `proofValue`,
				ProofFormatOptions: `{"kid":{}, "proofPurpose":"authentication",
							"created":"2019-04-16T18:11:09-04:00"}`,
				err: "failed to prepare signing opts",
			},
			{
				name:        "invalid signing opts",
				ProofFormat: `proofValue`,
				ProofFormatOptions: `{"kid":"", "proofPurpose":{},
							"created":"2019-04-16T18:11:09-04:00"}`,
				err: "failed to prepare signing opts",
			},
			{
				name:        "invalid signing opts",
				ProofFormat: `proofValue`,
				ProofFormatOptions: `{"kid":"", "proofPurpose":{},
							"created":"xyz"}`,
				err: "failed to prepare signing opts",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				opts, err := getComposeSigningOpts(&ComposeCredentialRequest{
					ProofFormatOptions: json.RawMessage([]byte(tc.ProofFormatOptions)),
					ProofFormat:        tc.ProofFormat,
				})

				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				require.NoError(t, err)
				require.NotEmpty(t, opts)
			})
		}
	})
}

func TestGenerateKeypair(t *testing.T) {
	t.Run("generate key pair - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager: &kms.KeyManager{CreateKeyID: "key-1", CreateKeyValue: kh,
				ExportPubKeyBytesValue: pubKey},
		})
		require.NoError(t, err)

		generateKeypairHandler := getHandler(t, op, generateKeypairPath, issuerMode)

		rr := serveHTTP(t, generateKeypairHandler.Handle(), http.MethodGet, generateKeypairPath, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		generateKeypairResp := make(map[string]interface{})

		err = json.Unmarshal(rr.Body.Bytes(), &generateKeypairResp)
		require.NoError(t, err)
		require.NotEmpty(t, generateKeypairResp["publicKey"])
	})

	t.Run("generate key pair - failure", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: mem.NewProvider(),
			StoreProvider:      memstore.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		})
		require.NoError(t, err)
		op.kms = &kms.KeyManager{CreateKeyErr: errors.New("kms - create keyset error")}

		generateKeypairHandler := getHandler(t, op, generateKeypairPath, issuerMode)

		rr := serveHTTP(t, generateKeypairHandler.Handle(), http.MethodGet, generateKeypairPath, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create key pair")
	})
}

func TestCredentialVerifications(t *testing.T) {
	vc, err := verifiable.NewUnverifiedCredential([]byte(prCardVC))
	require.NoError(t, err)

	vc.Context = append(vc.Context, cslstatus.Context)

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:             &cryptomock.Crypto{},
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	endpoint := credentialsVerificationEndpoint
	didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

	verificationsHandler := getHandler(t, op, endpoint, verifierMode)

	t.Run("credential verification - success", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		ops, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		ops.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}
		cslBytes, err := json.Marshal(&cslstatus.CSL{})
		require.NoError(t, err)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

		vc.Status = &verifiable.TypedID{
			ID:   "http://example.com/status/100",
			Type: "CredentialStatusList2017",
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, endpoint, verifierMode)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, string(vcBytes), verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		verificationResp := &CredentialsVerificationSuccessResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 2, len(verificationResp.Checks))
	})

	t.Run("credential verification - request doesn't contain checks", func(t *testing.T) {
		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		// verify that the default check was performed
		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable credential doesn't contains proof", verificationResp.Checks[0].Error)
	})

	t.Run("credential verification - invalid credential", func(t *testing.T) {
		req := &CredentialsVerificationRequest{
			Credential: []byte(testIssuerProfileWithDID),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request: build new credential")
	})

	t.Run("credential verification - proof check failure", func(t *testing.T) {
		// no proof in VC
		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable credential doesn't contains proof", verificationResp.Checks[0].Error)

		// proof validation error (DID not found)
		req = &CredentialsVerificationRequest{
			Credential: []byte(validVCWithProof),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp = &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, "verifiable credential proof validation error")
	})

	t.Run("credential verification - status check failure", func(t *testing.T) {
		t.Run("status check failure - error fetching status", func(t *testing.T) {
			vc.Status = &verifiable.TypedID{
				ID: "http://example.com/status/100",
			}

			vcBytes, err := vc.MarshalJSON()
			require.NoError(t, err)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, err := json.Marshal(req)
			require.NoError(t, err)

			rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "failed to fetch the status")
		})

		t.Run("status check failure - revoked", func(t *testing.T) {
			cslBytes, err := json.Marshal(&cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{
				strings.ReplaceAll(validVCStatus, "#ID", "https://issuer.oidp.uscis.gov/credentials/83627465"),
				strings.ReplaceAll(validVCStatus, "#ID", "http://example.edu/credentials/1872")}})
			require.NoError(t, err)
			op.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
				Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

			vc.Status = &verifiable.TypedID{
				ID: "http://example.com/status/100",
			}

			vcBytes, err := vc.MarshalJSON()
			require.NoError(t, err)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, err := json.Marshal(req)
			require.NoError(t, err)

			rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "Revoked")
		})
	})

	t.Run("credential verification - invalid check", func(t *testing.T) {
		invalidCheckName := "invalidCheckName"

		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{invalidCheckName},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, invalidCheckName, verificationResp.Checks[0].Check)
		require.Equal(t, "check not supported", verificationResp.Checks[0].Error)
	})

	t.Run("credential verification - invalid json input", func(t *testing.T) {
		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint,
			[]byte("invalid input"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("credential verification - invalid challenge and domain", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		// verify credential
		handler := getHandler(t, op, endpoint, verifierMode)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, verificationMethod, domain,
				"invalid-challenge"),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, verificationMethod, "invalid-domain", challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck},
				Domain:    domain,
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")

		// fail when proof has challenge and no challenge in the options
		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, verificationMethod, domain, challenge),
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		// fail when proof has domain and no domain in the options
		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")
	})

	t.Run("credential verification - invalid vc proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.AssertionMethod = nil
		verificationMethod := didDoc.PublicKey[0].ID

		ops, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		ops.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}
		cslBytes, err := json.Marshal(&cslstatus.CSL{})
		require.NoError(t, err)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

		vc.Status = &verifiable.TypedID{
			ID:   "http://example.com/status/100",
			Type: "CredentialStatusList2017",
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, endpoint, verifierMode)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, string(vcBytes), verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable credential proof purpose validation error :"+
			" unable to find matching assertionMethod key IDs for given verification method")
	})
}

func TestVerifyPresentation(t *testing.T) {
	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:             &cryptomock.Crypto{},
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	endpoint := presentationsVerificationEndpoint
	verificationsHandler := getHandler(t, op, endpoint, verifierMode)

	t.Run("presentation verification - success", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		// verify credential
		handler := getHandler(t, op, endpoint, verifierMode)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		verificationResp := &VerifyPresentationSuccessResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0])
	})

	t.Run("presentation verification - request doesn't contain checks", func(t *testing.T) {
		req := &VerifyPresentationRequest{
			Presentation: []byte(vpWithoutProof),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		// verify that the default check was performed
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable presentation proof validation error : embedded proof is missing",
			verificationResp.Checks[0].Error)
	})

	t.Run("presentation verification - proof check failure", func(t *testing.T) {
		// no proof in VC
		req := &VerifyPresentationRequest{
			Presentation: []byte(vpWithoutProof),
			Opts: &VerifyPresentationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable presentation proof validation error : embedded proof is missing",
			verificationResp.Checks[0].Error)

		// proof validation error (DID not found)
		req = &VerifyPresentationRequest{
			Presentation: []byte(validVCWithProof),
			Opts: &VerifyPresentationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp = &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, "proof validation error")
	})

	t.Run("presentation verification - invalid check", func(t *testing.T) {
		invalidCheckName := "invalidCheckName"

		req := &VerifyPresentationRequest{
			Presentation: []byte(validVP),
			Opts: &VerifyPresentationOptions{
				Checks: []string{invalidCheckName},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, invalidCheckName, verificationResp.Checks[0].Check)
		require.Equal(t, "check not supported", verificationResp.Checks[0].Error)
	})

	t.Run("presentation verification - invalid json input", func(t *testing.T) {
		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint,
			[]byte("invalid input"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("presentation verification - invalid challenge and domain", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:xyz"

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		// verify credential
		handler := getHandler(t, op, endpoint, verifierMode)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, domain, uuid.New().String()),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Domain:    domain,
				Challenge: challenge,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, "invalid-domain", challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Domain:    domain,
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")

		// fail when proof has challenge and no challenge in the options
		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, domain, challenge),
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		// fail when proof has domain and no domain in the options
		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")
	})

	t.Run("presentation verification - invalid vp proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:xyz123"

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.Authentication = nil
		verificationMethod := didDoc.PublicKey[0].ID

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		// verify credential
		handler := getHandler(t, op, endpoint, verifierMode)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable presentation proof purpose validation error :"+
			" unable to find matching authentication key IDs for given verification method")
	})

	t.Run("presentation verification - invalid vc proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:abc123"

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.AssertionMethod = nil
		verificationMethod := didDoc.PublicKey[0].ID

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		// verify credential
		handler := getHandler(t, op, endpoint, verifierMode)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable credential proof purpose validation error : unable"+
			" to find matching assertionMethod key IDs for given verification method")
	})
}

func TestValidateProof(t *testing.T) {
	proof := make(map[string]interface{})
	key := "challenge"
	value := uuid.New().String()

	proof[key] = value

	// success
	err := validateProofData(proof, key, value)
	require.NoError(t, err)

	// fail - not a string
	proof[key] = 234
	err = validateProofData(proof, key, value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid challenge in the proof")

	// fail - invalid
	proof[key] = "invalid-data"
	err = validateProofData(proof, key, value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid challenge in the proof")
}

func TestValidateProofPurpose(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didID := "did:test:xyz123"

	didDoc := createDIDDoc(didID, pubKey)
	kid := didDoc.PublicKey[0].ID

	vdriReg := &vdrimock.MockVDRIRegistry{ResolveValue: didDoc}

	proof := make(map[string]interface{})
	key := "challenge"
	value := uuid.New().String()

	proof[proofPurpose] = assertionMethod
	proof[verificationMethod] = kid

	// success
	err = validateProofPurpose(proof, vdriReg)
	require.NoError(t, err)

	// fail - no value
	delete(proof, proofPurpose)
	err = validateProofPurpose(proof, vdriReg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof doesn't have purpose")

	proof[proofPurpose] = assertionMethod
	delete(proof, verificationMethod)
	err = validateProofPurpose(proof, vdriReg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof doesn't have verification method")

	// fail - not a string
	proof[proofPurpose] = 234
	err = validateProofPurpose(proof, vdriReg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof purpose is not a string")

	proof[proofPurpose] = assertionMethod
	proof[verificationMethod] = 234
	err = validateProofPurpose(proof, vdriReg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof verification method is not a string")

	// fail - invalid
	proof[key] = "invalid-data"
	err = validateProofData(proof, key, value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid challenge in the proof")
}

func TestCreateHolderProfile(t *testing.T) {
	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:             &cryptomock.Crypto{},
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	op.didBlocClient = &didbloc.Client{CreateDIDValue: createDefaultDID()}

	endpoint := holderProfileEndpoint
	handler := getHandler(t, op, endpoint, holderMode)

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
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{},
		})
		require.NoError(t, err)

		vReq := &HolderProfileRequest{
			Name: "profile",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		handler := getHandler(t, ops, endpoint, holderMode)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did public key")
	})
}

func TestGetHolderProfile(t *testing.T) {
	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{
		Crypto:             &cryptomock.Crypto{},
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		VDRI:               &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	op.didBlocClient = &didbloc.Client{CreateDIDValue: createDefaultDID()}

	endpoint := getHolderProfileEndpoint
	handler := getHandler(t, op, endpoint, holderMode)

	urlVars := make(map[string]string)

	t.Run("get profile - success", func(t *testing.T) {
		vReq := &vcprofile.HolderProfile{
			Name:          "test",
			SignatureType: vccrypto.Ed25519Signature2018,
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

func TestSignPresentation(t *testing.T) {
	endpoint := "/test/prove/presentations"
	keyID := "key-333"
	issuerProfileDIDKey := "did:test:abc#" + keyID

	vReq := &vcprofile.HolderProfile{
		Name:          "test",
		SignatureType: vccrypto.Ed25519Signature2018,
		Creator:       issuerProfileDIDKey,
	}

	kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      memstore.NewProvider(),
		KMSSecretsProvider: mem.NewProvider(),
		KeyManager:         &kms.KeyManager{CreateKeyID: keyID, CreateKeyValue: kh},
		Crypto:             &cryptomock.Crypto{},
	})
	require.NoError(t, err)

	err = op.profileStore.SaveHolderProfile(vReq)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = vReq.Name

	handler := getHandler(t, op, signPresentationEndpoint, holderMode)

	t.Run("sign presentation - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		closeableKMS := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyID: keyID, CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDocWithKeyID(didID, keyID, base58.Decode(signingKey)), nil
				},
			},
			Crypto: &cryptomock.Crypto{},
		})
		require.NoError(t, err)

		vReq.SignatureRepresentation = verifiable.SignatureJWS
		vReq.OverwriteHolder = true
		vReq.DID = "did:trustbloc:xyz"

		err = ops.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, signPresentationEndpoint, holderMode)

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
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		closeableKMS := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := closeableKMS.CreateKeySet()
		require.NoError(t, err)

		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyID: keyID, CreateKeyValue: kh},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDocWithKeyID(didID, keyID, base58.Decode(signingKey)), nil
				},
			},
			Crypto: &cryptomock.Crypto{},
		})
		require.NoError(t, err)

		vReq.SignatureRepresentation = verifiable.SignatureJWS

		err = ops.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, signPresentationEndpoint, holderMode)

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
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		ops, err := New(&Config{
			StoreProvider:      memstore.NewProvider(),
			Crypto:             &cryptomock.Crypto{},
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
		})
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, signPresentationEndpoint, holderMode)

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
			Presentation: []byte(invalidVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable presentation is not valid")
	})

	t.Run("sign presentation - signing error", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
		require.NoError(t, err)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{},
			StoreProvider:      memstore.NewProvider(),
			KMSSecretsProvider: mem.NewProvider(),
			KeyManager:         &kms.KeyManager{CreateKeyValue: kh},
			VDRI:               &vdrimock.MockVDRIRegistry{ResolveErr: errors.New("resolve error")},
		})
		require.NoError(t, err)

		vReq.Creator = "not a did"

		err = op.profileStore.SaveHolderProfile(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, op, signPresentationEndpoint, holderMode)

		req := &SignPresentationRequest{
			Presentation: []byte(validVP),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign presentation")
	})
}

func TestGetPublicKeyID(t *testing.T) {
	t.Run("Test decode public key", func(t *testing.T) {
		tests := []struct {
			name     string
			didStr   string
			expected string
			err      string
		}{
			{
				name: "Test when first public is not 'Ed25519VerificationKey2018' and id is not in DID format",
				didStr: `{
    "id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ",
    "@context": ["https://www.w3.org/ns/did/v1", "https://docs.example.com/contexts/sample/sample-v0.1.jsonld"],
    "publicKey": [{
        "id": "#5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA",
        "usage": "signing",
        "publicKeyJwk": {
            "x": "DSE4CfCVKNgxNMDV6dK_DbcwshievbxwHJwOsGoSpaw",
            "kty": "EC",
            "crv": "secp256k1",
            "y": "xzrnm-VHA22nfGrNGGaLL9aPHRN26qyJNli3jByQSfQ",
            "kid": "5hgq2bNVTqyns_Nvcc_ybVHnFMx33_dAsfrfpZMTqTA"
        },
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }, {
        "publicKeyHex": "020d213809f09528d83134c0d5e9d2bf0db730b2189ebdbc701c9c0eb06a12a5ac",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "id": "#primary",
        "usage": "signing",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }, {
        "publicKeyHex": "02d5a045f28c14b3d5971b0df9aabd8ee44a3e3af52a1a14a206327991c6e54a80",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "id": "#recovery",
        "usage": "recovery",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }, {
        "type": "Ed25519VerificationKey2018",
        "publicKeyBase58": "GUXiqNHCdirb6NKpH6wYG4px3YfMjiCh6dQhU3zxQVQ7",
        "id": "#signing-key",
        "usage": "signing",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }]
}`,
				expected: "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
			},
			{
				name: "Test when first public is not 'Ed25519VerificationKey2018' and id is in DID format",
				didStr: `{
    "id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ",
    "@context": ["https://www.w3.org/ns/did/v1", "https://docs.example.com/contexts/sample/sample-v0.1.jsonld"],
    "publicKey": [{
        "publicKeyHex": "02d5a045f28c14b3d5971b0df9aabd8ee44a3e3af52a1a14a206327991c6e54a80",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#recovery",
        "usage": "recovery",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }, {
        "type": "Ed25519VerificationKey2018",
        "publicKeyBase58": "GUXiqNHCdirb6NKpH6wYG4px3YfMjiCh6dQhU3zxQVQ7",
        "id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
        "usage": "signing",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }]
}`,
				expected: "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
			},
			{
				name: "Test with no public keys or authentication",
				didStr: `{
    "id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ",
    "@context": ["https://www.w3.org/ns/did/v1", "https://docs.example.com/contexts/sample/sample-v0.1.jsonld"],
    "publicKey": []
}`,
				err: "public key not found in DID Document",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				doc, err := did.ParseDocument([]byte(tc.didStr))
				require.NoError(t, err)
				require.NotNil(t, doc)

				id, err := getPublicKeyID(doc, "", vccrypto.Ed25519Signature2018)
				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.expected, id)
			})
		}
	})
}

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

func serveHTTPMux(t *testing.T, handler Handler, endpoint string, reqBytes []byte,
	urlVars map[string]string) *httptest.ResponseRecorder {
	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
}

func getProfileRequest() *ProfileRequest {
	return &ProfileRequest{
		Name:          "issuer",
		URI:           "http://example.com/credentials",
		SignatureType: "Ed25519Signature2018"}
}

func getHandler(t *testing.T, op *Operation, lookup, mode string) Handler {
	return getHandlerWithError(t, op, lookup, mode)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup, mode string) Handler {
	return handlerLookup(t, op, lookup, mode)
}

func handlerLookup(t *testing.T, op *Operation, lookup, mode string) Handler {
	handlers, err := op.GetRESTHandlers(mode)
	require.NoError(t, err)
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func getTestProfile() *vcprofile.DataProfile {
	return &vcprofile.DataProfile{
		Name:          "test",
		DID:           "did:test:abc",
		URI:           "https://test.com/credentials",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:test:abc#key1",
	}
}

func createDefaultDID() *did.Doc {
	const (
		didID = "did:local:abc"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return createDIDDoc(didID, pubKey)
}

func createDIDDoc(didID string, pubKey []byte) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	creator := didID + "#key-1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: "https://agent.example.com/",
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		PublicKey:            []did.PublicKey{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.VerificationMethod{{PublicKey: signingKey}},
		Authentication:       []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityInvocation: []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityDelegation: []did.VerificationMethod{{PublicKey: signingKey}},
	}
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

	signingKey := did.PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		PublicKey:            []did.PublicKey{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.VerificationMethod{{PublicKey: signingKey}},
		Authentication:       []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityInvocation: []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityDelegation: []did.VerificationMethod{{PublicKey: signingKey}},
	}
}
func setMockEDVClientReadDocumentReturnValue(t *testing.T, client *edv.Client, op *Operation,
	structuredDocForSubsequentCalls string) {
	firstEncryptedDocToReturn := prepareEncryptedDocument(t, op, testStructuredDocument1)
	subsequentEncryptedDocToReturn := prepareEncryptedDocument(t, op, structuredDocForSubsequentCalls)

	client.ReadDocumentFirstReturnValue = &firstEncryptedDocToReturn
	client.ReadDocumentSubsequentReturnValue = &subsequentEncryptedDocToReturn
}

func prepareEncryptedDocument(t *testing.T, op *Operation, structuredDoc string) models.EncryptedDocument {
	jwe, err := op.jweEncrypter.Encrypt([]byte(structuredDoc), nil)
	require.NoError(t, err)

	serializedJWE, err := jwe.Serialize(json.Marshal)
	require.NoError(t, err)

	encryptedDocToReturn := models.EncryptedDocument{
		ID:       "",
		Sequence: 0,
		JWE:      []byte(serializedJWE),
	}

	return encryptedDocToReturn
}

type mockResponseWriter struct {
}

func (b mockResponseWriter) Header() http.Header {
	panic("implement me")
}

func (b mockResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("response writer failed")
}

func (b mockResponseWriter) WriteHeader(statusCode int) {
}

type mockStore struct {
	put func(string, []byte) error
	get func(string) ([]byte, error)
}

// Put stores the key and the record
func (m *mockStore) Put(k string, v []byte) error {
	return m.put(k, v)
}

// Get fetches the record based on key
func (m *mockStore) Get(k string) ([]byte, error) {
	return m.get(k)
}

// CreateIndex creates an index in the store based on the provided CreateIndexRequest.
func (m *mockStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return nil
}

// Query queries the store for data based on the provided query string, the format of
// which will be dependent on what the underlying store requires.
func (m *mockStore) Query(query string) (storage.ResultsIterator, error) {
	return nil, nil
}

type TestClient struct {
	edvServerURL string
}

// NewMockEDVClient
func NewMockEDVClient(edvServerURL string) *TestClient {
	return &TestClient{edvServerURL: edvServerURL}
}

// CreateDataVault sends the EDV server a request to create a new data vault.
func (c *TestClient) CreateDataVault(config *models.DataVaultConfiguration) (string, error) {
	return "", nil
}

// CreateDocument sends the EDV server a request to store the specified document.
func (c *TestClient) CreateDocument(vaultID string, document *models.EncryptedDocument) (string, error) {
	return "", errVaultNotFound
}

// RetrieveDocument sends the Mock EDV server a request to retrieve the specified document.
func (c *TestClient) ReadDocument(vaultID, docID string) (*models.EncryptedDocument, error) {
	return nil, errDocumentNotFound
}

func (c *TestClient) QueryVault(vaultID string, query *models.Query) ([]string, error) {
	return []string{"dummyID"}, nil
}

type mockVCStatusManager struct {
	createStatusIDValue *verifiable.TypedID
	createStatusIDErr   error
	updateVCStatusErr   error
	getCSLValue         *cslstatus.CSL
	getCSLErr           error
}

func (m *mockVCStatusManager) CreateStatusID() (*verifiable.TypedID, error) {
	return m.createStatusIDValue, m.createStatusIDErr
}

func (m *mockVCStatusManager) UpdateVCStatus(v *verifiable.Credential, profile *vcprofile.DataProfile,
	status, statusReason string) error {
	return m.updateVCStatusErr
}

func (m *mockVCStatusManager) GetCSL(id string) (*cslstatus.CSL, error) {
	return m.getCSLValue, m.getCSLErr
}

type mockHTTPClient struct {
	doValue *http.Response
	doErr   error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.doValue, m.doErr
}

func getSignedVC(t *testing.T, privKey []byte, vcJSON, verificationMethod, domain, challenge string) []byte {
	vc, err := verifiable.NewUnverifiedCredential([]byte(vcJSON))
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	signerSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithCompactProof())
	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   signerSuite,
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &created,
		VerificationMethod:      verificationMethod,
		Domain:                  domain,
		Challenge:               challenge,
		Purpose:                 vccrypto.AssertionMethod,
	})
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	signedVC, err := vc.MarshalJSON()
	require.NoError(t, err)

	return signedVC
}

func getSignedVP(t *testing.T, privKey []byte, vcJSON, verificationMethod, domain, challenge string) []byte { // nolint
	signedVC := getSignedVC(t, privKey, vcJSON, verificationMethod, "", "")

	vc, err := verifiable.NewUnverifiedCredential(signedVC)
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	vp, err := vc.Presentation()
	require.NoError(t, err)

	signerSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithCompactProof())
	err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   signerSuite,
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &created,
		VerificationMethod:      verificationMethod,
		Domain:                  domain,
		Challenge:               challenge,
		Purpose:                 vccrypto.Authentication,
	})
	require.NoError(t, err)

	signedVP, err := vp.MarshalJSON()
	require.NoError(t, err)

	return signedVP
}

type ed25519TestSigner struct {
	privateKey []byte
}

func (s *ed25519TestSigner) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}
func getEd25519TestSigner(privKey []byte) *ed25519TestSigner {
	return &ed25519TestSigner{privateKey: privKey}
}

type mockCredentialStatusManager struct {
	CreateErr error
}

func (m *mockCredentialStatusManager) CreateStatusID() (*verifiable.TypedID, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	return nil, nil
}

func (m *mockCredentialStatusManager) UpdateVCStatus(v *verifiable.Credential,
	profile *vcprofile.DataProfile, status, statusReason string) error {
	return nil
}

func (m *mockCredentialStatusManager) GetCSL(id string) (*cslstatus.CSL, error) {
	return nil, nil
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
