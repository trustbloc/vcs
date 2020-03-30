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
	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/mock/didbloc"
	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
)

const (
	multipleContext = `"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/citizenship/v1"]`
	validContext    = `"@context":["https://www.w3.org/2018/credentials/v1"]`
	invalidContext  = `"@context":"https://www.w3.org/2018/credentials/v1"`

	testCreateCredentialRequest = `{` +
		validContext + `,
"type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "profile": "test"
}`
	testInvalidContextCreateCredentialRequest = `{` +
		invalidContext + `,
"type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "university": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "profile": "test"
}`
	testMultipleContextCreateCredentialRequest = `{` +
		multipleContext + `,
"type": [
    "VerifiableCredential",
    "PermanentResidentCard"
  ],
  "credentialSubject": {
    "id": "did:example:b34ca6cd37bbf23",
    "type": ["PermanentResident", "Person"],
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
  },
  "profile": "test"
}`

	testInvalidProfileForCreateCredential = `{
  "profile": "invalid"
}`

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
"profile": "issuer",
"credential" : ""
}`

	testStoreIncorrectCredentialRequest = `{
"profile": "",
"credential" : "{\"@context\":\"https:\/\/www.w3.org\/2018\/credentials\/v1\",\"id\":\` +
		`"http:\/\/example.edu\/credentials\/1872\",\"type\":\"VerifiableCredential\",\"credentialSubject\":{\"id\` +
		`":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"},\"issuer\":{\"id\":\"did:example:76e12ec712ebc6f1c221ebfeb1f\` +
		`",\"name\":\"Example University\"},\"issuanceDate\":\"2010-01-01T19:23:24Z\"}"
}`

	testIncorrectCredential = `{` +
		validContext + `,
		"credentialSubject": {
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"degree": {
		"type": "BachelorDegree",
		"university": "MIT"
		},
		"name": "Jayden Doe",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
		},
		"profile": "test"
}`
	testIssuerProfile = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018"
}`
	testIssuerProfileWithDID = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
        "did": "did:peer:22",
        "didPrivateKey": "key"
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
	invalidVCStatus = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "credentialSchema": [],
  "credentialSubject": {
    "currentStatus": "Revoked",
    "statusReason": "Disciplinary action"
  },
  "id": "#ID",
  "type": "VerifiableCredential"
}`

	testDocID = "VJYHHJx4C8J9Fsgz7rZqSp"

	testStructuredDocument = `{
 "id":"someID",
 "meta": {
   "created": "2019-06-18"
 },
 "content": {
   "message": "Hello World!"
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

	invalidVP = `{` +
		validContext + `,
  "type": "VerifiablePresentation",
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-01-21T16:44:53+02:00",
    "proofValue": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQ` +
		`y7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4v` +
		`GHSrQyHUGlcTwLtjPAnKb78"
  }
}`

	invalidVCinVP = `{` +
		validContext + `,
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "id": "http://example.edu/credentials/1872",
      "type": [
        "VerifiableCredential",
        "AlumniCredential"
      ],
      "issuer": "https://example.edu/issuers/565049",
      "issuanceDate": "2010-01-01T19:03:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {
          "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
          "name": [
            {
              "value": "Example University",
              "lang": "en"
            }
          ]
        }
      }
    }
  ],
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-01-21T16:44:53+02:00",
    "proofValue": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQ` +
		`y7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4v` +
		`GHSrQyHUGlcTwLtjPAnKb78"
  }
}`
)

// errVaultNotFound throws an error when vault is not found
var errVaultNotFound = errors.New("vault not found")

// errDocumentNotFound throws an error when document associated with ID is not found
var errDocumentNotFound = errors.New("edv does not have a document associated with ID")

var errFailOnSecondOpenMockProvider = errors.New("i always fail the second time")

func TestNew(t *testing.T) {
	t.Run("test error from opening credential store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: &mockstore.Provider{ErrOpenStoreHandle: fmt.Errorf("error open store")},
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, op)
	})
	t.Run("fail to create credential store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: &mockstore.Provider{
			ErrCreateStore: fmt.Errorf("create error")}, EDVClient: client,
			KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create error")
		require.Nil(t, op)
	})
	t.Run("fail to open ID mapping store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: &FailOnSecondOpenMockProvider{}, EDVClient: client,
			KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.Equal(t, errFailOnSecondOpenMockProvider, err)
		require.Nil(t, op)
	})
	t.Run("test error from csl", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: &mockstore.Provider{FailNameSpace: "credentialstatus"},
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to instantiate new csl status")
		require.Nil(t, op)
	})
}

func TestCreateCredentialHandlerIssuer(t *testing.T) {
	const (
		issuerMode   = "issuer"
		combinedMode = "combined"
	)

	testCreateCredentialHandlerIssuer(t, issuerMode)
	testCreateCredentialHandlerIssuer(t, combinedMode)
}

func testCreateCredentialHandlerIssuer(t *testing.T, mode string) {
	client := edv.NewMockEDVClient("test", nil)

	kms := &kmsmock.CloseableKMS{}
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: client, KMS: &kmsmock.CloseableKMS{}, VDRI: &vdrimock.MockVDRIRegistry{},
		HostURL: "localhost:8080"})
	require.NoError(t, err)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	op.crypto = crypto.New(kms,
		&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{Value: []byte(pubKey)}, nil
		}})

	err = op.profileStore.SaveProfile(getTestProfile())
	require.NoError(t, err)

	createCredentialHandler := getHandler(t, op, createCredentialEndpoint, mode)

	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	t.Run("create credential success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testCreateCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.Contains(t, rr.Body.String(), validContext)
		require.Contains(t, rr.Body.String(), getTestProfile().DID)
		require.Contains(t, rr.Body.String(), getTestProfile().Name)
	})
	t.Run("create credential with multiple contexts success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testMultipleContextCreateCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.Contains(t, rr.Body.String(), multipleContext)
		require.Contains(t, rr.Body.String(), getTestProfile().DID)
		require.Contains(t, rr.Body.String(), getTestProfile().Name)
	})
	t.Run("create credential error by passing invalid context", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testInvalidContextCreateCredentialRequest)))
		require.NoError(t, err)

		body, err := ioutil.ReadAll(req.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), invalidContext)

		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, invalidRequestErrMsg+": EOF", rr.Body.String())
	})
	t.Run("create credential error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, invalidRequestErrMsg+": EOF", rr.Body.String())
	})
	t.Run("create credential error by passing invalid profile name", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testInvalidProfileForCreateCredential)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to read profile")
	})
	t.Run("create credential error by passing invalid credential object", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testIncorrectCredential)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create credential")
	})
	t.Run("create credential error unable to write a response while reading the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createCredentialHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Unable to send error message, response writer failed")
	})
	t.Run("test error from create status id", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		err = op.profileStore.SaveProfile(getTestProfile())
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{createStatusIDErr: fmt.Errorf("error create status id")}

		createCredentialHandler := getHandler(t, op, createCredentialEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
			bytes.NewBuffer([]byte(testCreateCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create status id for vc")
	})
}

func TestCreateCredentialHandler_SignatureError(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil)
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
	require.NoError(t, err)

	err = op.profileStore.SaveProfile(getTestProfile())
	require.NoError(t, err)

	createCredentialHandler := getHandler(t, op, createCredentialEndpoint, "issuer")

	req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint,
		bytes.NewBuffer([]byte(testCreateCredentialRequest)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	createCredentialHandler.Handle().ServeHTTP(rr, req)
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Contains(t, rr.Body.String(), "failed to sign credential")
}

func TestVerifyPresentationHandlerIssuer(t *testing.T) {
	const (
		verifierMode = "verifier"
		combinedMode = "combined"
	)

	testVerifyPresentationHandlerIssuer(t, verifierMode)
	testVerifyPresentationHandlerIssuer(t, combinedMode)
}

func testVerifyPresentationHandlerIssuer(t *testing.T, mode string) {
	client := edv.NewMockEDVClient("test", nil)
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: client, KMS: &kmsmock.CloseableKMS{}, VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
	require.NoError(t, err)

	op.vcStatusManager = &mockVCStatusManager{getCSLValue: &cslstatus.CSL{}}

	verifyPresentationHandler := getHandler(t, op, verifyPresentationEndpoint, mode)

	t.Run("verify presentation success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyPresentationEndpoint, bytes.NewBuffer([]byte(validVP)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		verifyPresentationHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, "success", response.Message)
		require.Equal(t, true, response.Verified)
	})

	t.Run("verify presentation failure", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyPresentationEndpoint, bytes.NewBuffer([]byte(invalidVP)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyPresentationHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, false, response.Verified)
		require.Equal(t, "verifiable presentation is not valid:\n- (root):"+
			" verifiableCredential is required\n", response.Message)
	})
	t.Run("verify presentation failure", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyPresentationEndpoint, bytes.NewBuffer([]byte(invalidVP)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyPresentationHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, false, response.Verified)
		require.Equal(t, "verifiable presentation is not valid:\n- (root):"+
			" verifiableCredential is required\n", response.Message)
	})

	t.Run("invalid credential inside presentation", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyPresentationEndpoint, bytes.NewBuffer([]byte(invalidVCinVP)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyPresentationHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, false, response.Verified)
		require.Equal(t, "build new credential: fill credential context from raw: credential context of "+
			"unknown type", response.Message)
	})

	t.Run("test error while reading http request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyPresentationEndpoint, nil)
		require.NoError(t, err)

		req.Body = &mockReader{}
		rr := httptest.NewRecorder()

		verifyPresentationHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "reader error")
	})
}

func TestVerifyCredentialHandlerIssuer(t *testing.T) {
	const (
		issuerMode   = "issuer"
		combinedMode = "combined"
	)

	testVerifyCredentialHandlerIssuer(t, issuerMode)
	testVerifyCredentialHandlerIssuer(t, combinedMode)
}

func testVerifyCredentialHandlerIssuer(t *testing.T, mode string) {
	client := edv.NewMockEDVClient("test", nil)
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
	require.NoError(t, err)

	cslBytes, err := json.Marshal(&cslstatus.CSL{})
	require.NoError(t, err)

	op.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
		Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

	verifyCredentialHandler := getHandler(t, op, verifyCredentialEndpoint, mode)

	t.Run("verify credential success", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(validVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, true, response.Verified)
		require.Equal(t, "success", response.Message)
	})

	t.Run("test error while reading http request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, nil)
		require.NoError(t, err)

		req.Body = &mockReader{}
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "reader error")
	})

	t.Run("test error due to passing invalid credential object", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(invalidVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, false, response.Verified)
		require.Contains(t, response.Message, "unsupported format of issuer")
	})

	t.Run("test error from get CSL", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		op.httpClient = &mockHTTPClient{doErr: fmt.Errorf("error get csl")}

		verifyCredentialHandler := getHandler(t, op, verifyCredentialEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(validVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "error get csl")
	})

	t.Run("test get CSL return 500", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		op.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusInternalServerError,
			Body: ioutil.NopCloser(strings.NewReader(""))}}

		verifyCredentialHandler := getHandler(t, op, verifyCredentialEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(validVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to read response body for status 500")
	})

	t.Run("test revoked credential", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		cslBytes, err := json.Marshal(&cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{
			strings.ReplaceAll(validVCStatus, "#ID", "http://example.edu/credentials/1873"),
			strings.ReplaceAll(validVCStatus, "#ID", "http://example.edu/credentials/1872")}})
		require.NoError(t, err)
		op.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

		verifyCredentialHandler := getHandler(t, op, verifyCredentialEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(validVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		response := VerifyCredentialResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Equal(t, false, response.Verified)
		require.Contains(t, response.Message,
			"Revoked")
	})

	t.Run("test error from parse vs status", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		cslBytes, err := json.Marshal(&cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{
			strings.ReplaceAll(invalidVCStatus, "#ID", "http://example.edu/credentials/1872")}})
		require.NoError(t, err)
		op.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

		verifyCredentialHandler := getHandler(t, op, verifyCredentialEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, verifyCredentialEndpoint, bytes.NewBuffer([]byte(validVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		verifyCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)

		require.Contains(t, rr.Body.String(), "failed to parse and verify status vc")
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
	client := edv.NewMockEDVClient("test", nil)
	s := make(map[string][]byte)
	s["profile_Example University"] = []byte(testIssuerProfile)
	op, err := New(&Config{StoreProvider: &mockstore.Provider{Store: &mockstore.MockStore{Store: s}},
		EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
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
		op, err := New(&Config{StoreProvider: &mockstore.Provider{
			Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
			EDVClient: edv.NewMockEDVClient("test", nil),
			KMS:       getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
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
		s["profile_Example University"] = []byte(testIssuerProfile)
		op, err := New(&Config{StoreProvider: &mockstore.Provider{Store: &mockstore.MockStore{Store: s}},
			EDVClient: edv.NewMockEDVClient("test", nil),
			KMS:       getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
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
	client := edv.NewMockEDVClient("test", nil)
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
		HostURL: "localhost:8080", Domain: "testnet"})
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

	t.Run("create profile success without creating did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t),
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

	t.Run("test public key not found", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t),
			VDRI: &vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{ID: "did1"}}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfileWithDID)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "public key not found in DID Document", rr.Body.String())
	})

	t.Run("test failed to resolve did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t),
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
		require.Equal(t, rr.Body.String(), "missing profile name")
	})
	t.Run("create profile error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, invalidRequestErrMsg+": EOF", rr.Body.String())
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
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
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
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: &kmsmock.CloseableKMS{},
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
	client := edv.NewMockEDVClient("test", nil)
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
		HostURL: "localhost:8080"})

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

func TestStoreVCHandler(t *testing.T) {
	t.Run("store vc success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("store vc fail while encrypting document", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: &kmsmock.CloseableKMS{}, VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "key is nil")
	})
	t.Run("store vc err while creating the document - vault not found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), errVaultNotFound.Error())
	})
	t.Run("store vc err missing profile name", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreIncorrectCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "missing profile name")
	})
	t.Run("store vc err unable to unmarshal vc", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: &kmsmock.CloseableKMS{}, VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequestBadVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "unable to unmarshal the VC: decode new credential: "+
			"embedded proof is not JSON: unexpected end of JSON input", rr.Body.String())
	})
}

func TestRetrieveVCHandler(t *testing.T) {
	t.Run("retrieve vc success", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)

		err = op.idMappingStore.Put(testURLQueryID, []byte(""))
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, r)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, `"Hello World!"`, rr.Body.String())
	})
	t.Run("retrieve vc error when missing profile name", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile name")
	})
	t.Run("retrieve vc error when missing vc ID", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		q := req.URL.Query()
		q.Add("profile", getTestProfile().Name)
		req.URL.RawQuery = q.Encode()
		op.retrieveVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing verifiable credential ID")
	})
	t.Run("retrieve vc error when no document is found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)

		err = op.idMappingStore.Put(testUUID, []byte(""))
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := req.URL.Query()
		q.Add("id", testUUID)
		q.Add("profile", getTestProfile().Name)
		req.URL.RawQuery = q.Encode()

		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, errDocumentNotFound.Error(), rr.Body.String())
	})
	t.Run("retrieve vc fail when writing document retrieval success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		var logContents bytes.Buffer
		log.SetOutput(&logContents)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)

		err = op.idMappingStore.Put(testURLQueryID, []byte(""))
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op)

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
	t.Run("retrieve vc fail when writing document retrieval success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		var logContents bytes.Buffer
		log.SetOutput(&logContents)

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)

		err = op.idMappingStore.Put(testURLQueryID, []byte(""))
		require.NoError(t, err)

		setMockEDVClientReadDocumentReturnValue(t, client, op)

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
	t.Run("fail to unpack", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", getTestEncryptedDocument())

		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)

		err = op.idMappingStore.Put(testURLQueryID, []byte(""))
		require.NoError(t, err)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, r)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Equal(t, `decrypted envelope unpacking failed: no key accessible key not found`,
			rr.Body.String())
	})
	t.Run("ID map doesn't contain the specified ID", func(t *testing.T) {
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: nil, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
			HostURL: "localhost:8080"})
		require.NoError(t, err)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, r)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, storage.ErrValueNotFound.Error(), rr.Body.String())
	})
}

func TestVCStatus(t *testing.T) {
	const mode = "issuer"

	t.Run("test error from get CSL", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{getCSLErr: fmt.Errorf("error get csl")}

		vcStatusHandler := getHandler(t, op, vcStatusEndpoint, mode)

		req, err := http.NewRequest(http.MethodGet, vcStatus+"/1", nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		vcStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "error get csl")
	})

	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&Config{StoreProvider: memstore.NewProvider(),
			EDVClient: client, KMS: getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{}, HostURL: "localhost:8080"})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{
			getCSLValue: &cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{}}}

		vcStatusHandler := getHandler(t, op, vcStatusEndpoint, mode)

		req, err := http.NewRequest(http.MethodGet, vcStatus+"/1", nil)
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
	op, err := New(&Config{StoreProvider: memstore.NewProvider(),
		EDVClient: edv.NewMockEDVClient("test", nil),
		KMS:       getTestKMS(t), VDRI: &vdrimock.MockVDRIRegistry{},
		HostURL: "localhost:8080"})

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

func TestBuildStructuredDoc(t *testing.T) {
	t.Run("ID map already contains the provided vc ID", func(t *testing.T) {
		provider := memstore.NewProvider()

		err := provider.CreateStore(IDMappingStoreName)
		require.NoError(t, err)

		idMappingStore, err := provider.OpenStore(IDMappingStoreName)
		require.NoError(t, err)
		require.NotNil(t, idMappingStore)

		const mappedID = "mappedID"

		err = idMappingStore.Put("testID", []byte(mappedID))
		require.NoError(t, err)

		op := Operation{idMappingStore: idMappingStore}

		storeVCRequest := StoreVCRequest{Credential: ""}

		vc := verifiable.Credential{ID: "testID"}

		doc, err := op.buildStructuredDoc(&storeVCRequest, &vc)
		require.NoError(t, err)
		require.Equal(t, mappedID, doc.ID)
	})
}

func TestIssueCredential(t *testing.T) {
	t.Run("issue credential - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		kms := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := kms.CreateKeySet()
		require.NoError(t, err)

		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
			VDRI: &vdrimock.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, e error) {
					return createDIDDoc(didID, base58.Decode(signingKey)), nil
				},
			},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:local:abc"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		signedVCResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok := signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:local:abc#key-1", proof["verificationMethod"])

		// use issuer DID for signing
		req.Opts.AssertionMethod = ""

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		signedVCResp = make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok = signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:example:76e12ec712ebc6f1c221ebfeb1f#key-1", proof["verificationMethod"])
	})

	t.Run("issue credential - invalid request", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath,
			[]byte("invalid json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), invalidRequestErrMsg)
	})

	t.Run("issue credential - invalid vc", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(invalidVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate credential")
	})

	t.Run("issue credential - invalid vc", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(invalidVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to validate credential")
	})

	t.Run("issue credential - DID not resolvable", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveErr: errors.New("did not found")},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to resolve DID")
	})

	t.Run("issue credential - DID doesn't contain Public key", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{}},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "public key not found in DID Document")
	})

	t.Run("issue credential - signing error", func(t *testing.T) {
		kms := &kmsmock.CloseableKMS{SignMessageErr: fmt.Errorf("error sign msg")}
		_, signingKey, err := kms.CreateKeySet()
		require.NoError(t, err)

		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", base58.Decode(signingKey))

		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           kms,
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, issuerMode)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, issueCredentialHandler.Handle(), http.MethodPost, issueCredentialPath, reqBytes)

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

	op, err := New(&Config{
		StoreProvider: memstore.NewProvider(),
		KMS:           &kmsmock.CloseableKMS{},
		VDRI:          &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	handler := getHandler(t, op, composeAndIssueCredentialPath, issuerMode)

	t.Run("compose and issue credential - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		kms := &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)}

		_, signingKey, err := kms.CreateKeySet()
		require.NoError(t, err)

		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", base58.Decode(signingKey))

		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

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
		rr := serveHTTP(t, restHandler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

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
		rr = serveHTTP(t, restHandler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		// validate the response
		vcResp, err = verifiable.NewUnverifiedCredential(rr.Body.Bytes())
		require.NoError(t, err)
		require.Equal(t, 1, len(vcResp.Types))
		require.Equal(t, "VerifiableCredential", vcResp.Types[0])

		credSubject, ok = vcResp.Subject.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, subject, credSubject["id"])

		// test - with proof format
		proofFormatOptions := make(map[string]interface{})
		proofFormatOptions[keyID] = "did:test:hd9712akdsaishda7"

		proofFormatOptionsJSON, err := json.Marshal(proofFormatOptions)
		require.NoError(t, err)

		req.Issuer = "different-did"
		req.ProofFormat = "jws"
		req.ProofFormatOptions = proofFormatOptionsJSON
		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTP(t, restHandler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)
		require.Equal(t, http.StatusOK, rr.Code)

		signedVCResp := make(map[string]interface{})
		err = json.Unmarshal(rr.Body.Bytes(), &signedVCResp)
		require.NoError(t, err)
		require.NotEmpty(t, signedVCResp["proof"])

		proof, ok := signedVCResp["proof"].(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, "Ed25519Signature2018", proof["type"])
		require.NotEmpty(t, proof["jws"])
		require.Equal(t, "did:test:hd9712akdsaishda7#key-1", proof["verificationMethod"])
	})

	t.Run("compose and issue credential - invalid request", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath,
			[]byte("invalid input"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("compose and issue credential - signing failure", func(t *testing.T) {
		req := &ComposeCredentialRequest{}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to sign credential")
	})

	t.Run("compose and issue credential - build credential error (termsOfUse)", func(t *testing.T) {
		req := `{
			"termsOfUse":"should be object or array"
		}`

		// invoke the endpoint
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, []byte(req))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to build credential")
	})

	t.Run("compose and issue credential - build credential error (claims)", func(t *testing.T) {
		req := `{
			"claims":"invalid"
		}`

		// invoke the endpoint
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, []byte(req))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to build credential")
	})

	t.Run("compose and issue credential - build credential error (evidence)", func(t *testing.T) {
		req := `{
			"evidence":"invalid"
		}`

		// invoke the endpoint
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, []byte(req))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to build credential")
	})

	t.Run("compose and issue credential - invalid proof format option", func(t *testing.T) {
		req := &ComposeCredentialRequest{
			ProofFormat: "invalid-proof-format-value",
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
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
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get DID for signing: json: cannot unmarshal number")
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
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, composeAndIssueCredentialPath, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to get DID for signing: invalid kid type")
	})
}

func TestGenerateKeypair(t *testing.T) {
	t.Run("generate key pair - success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{CreateSigningKeyValue: string(pubKey)},
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
		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
		})
		require.NoError(t, err)
		op.kms = &kmsmock.CloseableKMS{CreateKeyErr: errors.New("kms - create keyset error")}

		generateKeypairHandler := getHandler(t, op, generateKeypairPath, issuerMode)

		rr := serveHTTP(t, generateKeypairHandler.Handle(), http.MethodGet, generateKeypairPath, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create key pair")
	})
}

func TestCredentialVerifications(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: memstore.NewProvider(),
		KMS:           &kmsmock.CloseableKMS{},
		VDRI:          &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	endpoints := []string{credentialVerificationsEndpoint, credentialsVerificationEndpoint}

	for _, path := range endpoints {
		endpoint := path

		verificationsHandler := getHandler(t, op, endpoint, verifierMode)

		t.Run("credential verification - success", func(t *testing.T) {
			pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

			didDoc := createDIDDoc(didID, pubKey)
			verificationMethod := didDoc.PublicKey[0].ID

			op, err := New(&Config{
				StoreProvider: memstore.NewProvider(),
				KMS:           &kmsmock.CloseableKMS{},
				VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			})
			require.NoError(t, err)

			op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

			// verify credential
			handler := getHandler(t, op, endpoint, verifierMode)

			vReq := &CredentialsVerificationRequest{
				Credential: getSignedVC(t, privKey, validVC, verificationMethod),
				Opts: &CredentialsVerificationOptions{
					Checks: []string{proofCheck},
				},
			}

			vReqBytes, err := json.Marshal(vReq)
			require.NoError(t, err)

			rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

			require.Equal(t, http.StatusOK, rr.Code)

			verificationResp := &CredentialsVerificationSuccessResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, proofCheck, verificationResp.Checks[0])
		})

		t.Run("credential verification - request doesn't contain checks", func(t *testing.T) {
			req := &CredentialsVerificationRequest{
				Credential: []byte(validVC),
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

		t.Run("credential verification - proof check failure", func(t *testing.T) {
			// no proof in VC
			req := &CredentialsVerificationRequest{
				Credential: []byte(validVC),
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
			require.Contains(t, verificationResp.Checks[0].Error, "proof validation error")
		})

		t.Run("credential verification - invalid check", func(t *testing.T) {
			invalidCheckName := "invalidCheckName"

			req := &CredentialsVerificationRequest{
				Credential: []byte(validVC),
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
	}
}

func TestVerifyPresentation(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: memstore.NewProvider(),
		KMS:           &kmsmock.CloseableKMS{},
		VDRI:          &vdrimock.MockVDRIRegistry{},
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

		op, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			KMS:           &kmsmock.CloseableKMS{},
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NoError(t, err)

		op.didBlocClient = &didbloc.Client{CreateDIDValue: didDoc}

		// verify credential
		handler := getHandler(t, op, endpoint, verifierMode)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, validVC, verificationMethod),
			Opts: &VerifyPresentationOptions{
				Checks: []string{proofCheck},
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
		require.Equal(t, "proof validation error : embedded proof is missing", verificationResp.Checks[0].Error)
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
		require.Equal(t, "proof validation error : embedded proof is missing", verificationResp.Checks[0].Error)

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

				id, err := getPublicKeyID(doc)
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
		Context:   []string{didContext},
		ID:        didID,
		PublicKey: []did.PublicKey{signingKey},
		Service:   []did.Service{service},
		Created:   &createdTime,
	}
}

func getTestKMS(t *testing.T) *legacykms.BaseKMS {
	memProvider := mem.NewProvider()
	p := testProvider{storeProvider: memProvider}

	_, err := p.StorageProvider().OpenStore("test-storage")
	require.NoError(t, err)

	testKMS, err := legacykms.New(p)
	require.NoError(t, err)

	return testKMS
}

func getTestEncryptedDocument() *operation.EncryptedDocument {
	return &operation.EncryptedDocument{
		ID:       testDocID,
		Sequence: 0,
		JWE: []byte(`{"protected":"eyJlbmMiOiJjaGFjaGEyMHBvbHkxM` +
			`zA1X2lldGYiLCJ0eXAiOiJKV00vMS4wIiwiYWxnIjoiQXV0aGNyeXB0IiwicmVjaXBpZW50cyI6W3siZW5jcnlwdGVkX2tleSI6ImdLcXNYN` +
			`m1HUXYtS3oyelQzMndIbE5DUjFiVU54ZlRTd0ZYcFVWb3FIMjctQUN0bURpZHBQdlVRcEdKSDZqMDkiLCJoZWFkZXIiOnsia2lkIjoiNzd6e` +
			`WlNeHY0SlRzc2tMeFdFOWI1cVlDN2o1b3Fxc1VMUnFhcVNqd1oya1kiLCJzZW5kZXIiOiJiNmhrRkpXM2RfNmZZVjAtcjV0WEJoWnBVVmtrY` +
			`XhBSFBDUEZxUDVyTHh3aGpwdFJraTRURjBmTEFNcy1seWd0Ym9PQmtnUDhWNWlwaDdndEVNcTAycmFDTEstQm5GRWo3dWk5Rmo5NkRleFRlR` +
			`zl6OGdab1lveXY5ZE09IiwiaXYiOiJjNHMzdzBlRzhyZGhnaC1EZnNjOW5Cb3BYVHA1OEhNZiJ9fV19","iv":"e8mXGCAamvwYcdf2",` +
			`"ciphertext":"dLKWmjFyL-G1uqF588Ya0g10QModI-q0f7vw_v3_jhzskuNqX7Yx4aSD7x2jhUdat82kHS4qLYw8BuUGvGimI_sCQ9m3On` +
			`QTHSjZnpg7VWRqAULBC3MSTtBa1DtZjZL4C0Y=","tag":"W4yJzyuGYzuZtZMRv2bDUg=="}`),
	}
}

func setMockEDVClientReadDocumentReturnValue(t *testing.T, client *edv.Client, op *Operation) {
	encryptedDocToReturn := prepareEncryptedDocument(op, t)

	client.ReadDocumentReturnValue = &encryptedDocToReturn
}

func prepareEncryptedDocument(op *Operation, t *testing.T) operation.EncryptedDocument {
	// No recipients in this case, so we pass in the sender key as the recipient key as well
	encryptedStructuredDoc, err := op.packer.Pack([]byte(testStructuredDocument),
		base58.Decode(op.senderKey), [][]byte{base58.Decode(op.senderKey)})
	require.NoError(t, err)

	encryptedDocToReturn := operation.EncryptedDocument{
		ID:       "",
		Sequence: 0,
		JWE:      encryptedStructuredDoc,
	}

	return encryptedDocToReturn
}

type testProvider struct {
	storeProvider ariesstorage.Provider
	crypto        legacykms.KeyManager
}

func (p testProvider) LegacyKMS() legacykms.KeyManager {
	return p.crypto
}

func (p testProvider) StorageProvider() ariesstorage.Provider {
	return p.storeProvider
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

type mockReader struct{}

func (r *mockReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("reader error")
}

func (r *mockReader) Close() error {
	return nil
}

type TestClient struct {
	edvServerURL string
}

// NewMockEDVClient
func NewMockEDVClient(edvServerURL string) *TestClient {
	return &TestClient{edvServerURL: edvServerURL}
}

// CreateDataVault sends the EDV server a request to create a new data vault.
func (c *TestClient) CreateDataVault(config *operation.DataVaultConfiguration) (string, error) {
	return "", nil
}

// CreateDocument sends the EDV server a request to store the specified document.
func (c *TestClient) CreateDocument(vaultID string, document *operation.EncryptedDocument) (string, error) {
	return "", errVaultNotFound
}

// RetrieveDocument sends the Mock EDV server a request to retrieve the specified document.
func (c *TestClient) ReadDocument(vaultID, docID string) (*operation.EncryptedDocument, error) {
	return nil, errDocumentNotFound
}

type mockKeyResolver struct {
	publicKeyFetcherValue verifiable.PublicKeyFetcher
}

func (m *mockKeyResolver) PublicKeyFetcher() verifiable.PublicKeyFetcher {
	return m.publicKeyFetcherValue
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

// FailOnSecondOpenMockProvider is a mock provider that returns an err the second time the OpenStore method is called.
type FailOnSecondOpenMockProvider struct {
	numTimesOpenCalled int
}

// CreateStore never returns an error.
func (p *FailOnSecondOpenMockProvider) CreateStore(name string) error {
	return nil
}

// OpenStore returns an error the second time it's called, otherwise no error is returned.
func (p *FailOnSecondOpenMockProvider) OpenStore(name string) (storage.Store, error) {
	p.numTimesOpenCalled++

	if p.numTimesOpenCalled == 2 {
		return nil, errFailOnSecondOpenMockProvider
	}

	return nil, nil
}

// Close never returns an error.
func (p *FailOnSecondOpenMockProvider) Close() error {
	return nil
}

// CloseStore never returns an error.
func (p *FailOnSecondOpenMockProvider) CloseStore(name string) error {
	return nil
}

type mockHTTPClient struct {
	doValue *http.Response
	doErr   error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.doValue, m.doErr
}

func getSignedVC(t *testing.T, privKey []byte, vcJSON, verificationMethod string) []byte {
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
	})
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	signedVC, err := vc.MarshalJSON()
	require.NoError(t, err)

	return signedVC
}

func getSignedVP(t *testing.T, privKey []byte, vcJSON, verificationMethod string) []byte {
	signedVC := getSignedVC(t, privKey, vcJSON, verificationMethod)

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
