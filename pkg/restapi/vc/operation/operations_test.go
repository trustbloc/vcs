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

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"

	"github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
)

const multipleContext = `"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/citizenship/v1"]`

const validContext = `"@context":["https://www.w3.org/2018/credentials/v1"]`

const invalidContext = `"@context":"https://www.w3.org/2018/credentials/v1"`

const testCreateCredentialRequest = `{` +
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

const testInvalidContextCreateCredentialRequest = `{` +
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

const testMultipleContextCreateCredentialRequest = `{` +
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

const testInvalidProfileForCreateCredential = `{
  "profile": "invalid"
}`

const testUUID = "4aae6b86-8e42-4d14-8cf5-21772ccb24aa"

const testURLQueryID = "http://test.com/" + testUUID

const (
	testStoreCredentialRequest = `{
"profile": "issuer",
"credential" : "{\"@context\":\"https:\/\/www.w3.org\/2018\/credentials\/v1\",\"id\":\` +
		`"http:\/\/example.edu\/credentials\/1872\/` + testUUID + `\",\"type\":\` +
		`"VerifiableCredential\",\"credentialSubject\":{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"},` +
		`\"issuer\":{\"id\":\"did:example:76e12ec712ebc6f1c221ebfeb1f\",\"name\":\"Example University\"}` +
		`,\"issuanceDate\":\"2010-01-01T19:23:24Z\"}"
}`
)

const (
	testStoreCredentialRequestWithInvalidUUID = `{
"profile": "issuer",
"credential" : "{\"@context\":\"https:\/\/www.w3.org\/2018\/credentials\/v1\",\"id\":\` +
		`"http:\/\/example.edu\/credentials\/1872\/ThisIsAnInvalidUUID\",\"type\":\` +
		`"VerifiableCredential\",\"credentialSubject\":{\"id\":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"},` +
		`\"issuer\":{\"id\":\"did:example:76e12ec712ebc6f1c221ebfeb1f\",\"name\":\"Example University\"}` +
		`,\"issuanceDate\":\"2010-01-01T19:23:24Z\"}"
}`
)

const (
	testStoreCredentialRequestBadVC = `{
"profile": "issuer",
"credential" : ""
}`
)

const (
	testStoreIncorrectCredentialRequest = `{
"profile": "",
"credential" : "{\"@context\":\"https:\/\/www.w3.org\/2018\/credentials\/v1\",\"id\":\` +
		`"http:\/\/example.edu\/credentials\/1872\",\"type\":\"VerifiableCredential\",\"credentialSubject\":{\"id\` +
		`":\"did:example:ebfeb1f712ebc6f1c276e12ec21\"},\"issuer\":{\"id\":\"did:example:76e12ec712ebc6f1c221ebfeb1f\` +
		`",\"name\":\"Example University\"},\"issuanceDate\":\"2010-01-01T19:23:24Z\"}"
}`
)
const (
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
)

const testIssuerProfile = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018"
}`

const testIssuerProfileWithDID = `{
		"name": "issuer",
		"uri": "https://example.com/credentials",
		"signatureType": "Ed25519Signature2018",
        "did": "did:peer:22",
        "didPrivateKey": "key"
}`

const validVC = `{` +
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

const validVCStatus = `{
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

const invalidVCStatus = `{
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

// VC without issuer
const invalidVC = `{` +
	validContext + `,
  "id": "http://example.edu/credentials/1872",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "issuanceDate": "2010-01-01T19:23:24Z"
}`

const testStructuredDocument = `{
  "id":"someID",
  "meta": {
    "created": "2019-06-18"
  },
  "content": {
    "message": "Hello World!"
  }
}`

// errVaultNotFound throws an error when vault is not found
var errVaultNotFound = errors.New("vault not found")

// errDocumentNotFound throws an error when document associated with ID is not found
var errDocumentNotFound = errors.New("edv does not have a document associated with ID")

func TestNew(t *testing.T) {
	t.Run("test error from open store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&mockstore.Provider{ErrOpenStoreHandle: fmt.Errorf("error open store")},
			client, &kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, op)
	})

	t.Run("test error from csl", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(&mockstore.Provider{FailNameSpace: "credentialStatus"},
			client, &kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to instantiate new csl status")
		require.Nil(t, op)
	})
}

func TestCreateCredentialHandlerIssuer(t *testing.T) {
	const mode = "issuer"

	client := edv.NewMockEDVClient("test", nil)

	kms := &kmsmock.CloseableKMS{}
	op, err := New(memstore.NewProvider(), client, kms, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
	require.NoError(t, err)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	op.crypto = crypto.New(kms,
		&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (i interface{}, err error) {
			return []byte(pubKey), nil
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
		require.Equal(t, rr.Body.String(), "Failed to write response for invalid request received")
	})
	t.Run("create credential error by passing invalid request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createCredentialEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createCredentialHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "Failed to write response for invalid request received")
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
		kms := &kmsmock.CloseableKMS{}
		op, err := New(memstore.NewProvider(), client, kms, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
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
	op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{}, "localhost:8080")
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

func TestVerifyCredentialHandlerIssuer(t *testing.T) {
	const mode = "issuer"

	client := edv.NewMockEDVClient("test", nil)
	op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{}, "localhost:8080")
	require.NoError(t, err)

	op.vcStatusManager = &mockVCStatusManager{getCSLValue: &cslstatus.CSL{}}

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
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{getCSLErr: fmt.Errorf("error get csl")}

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
			"failed to get credential status list")
	})

	t.Run("test revoked credential", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{
			getCSLValue: &cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{
				strings.ReplaceAll(validVCStatus, "#ID", "http://example.edu/credentials/1873"),
				strings.ReplaceAll(validVCStatus, "#ID", "http://example.edu/credentials/1872")}}}

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
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{
			getCSLValue: &cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{
				strings.ReplaceAll(invalidVCStatus, "#ID", "http://example.edu/credentials/1872")}}}

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
	const mode = "issuer"

	client := edv.NewMockEDVClient("test", nil)
	s := make(map[string][]byte)
	s["profile_Example University"] = []byte(testIssuerProfile)
	op, err := New(&mockstore.Provider{Store: &mockstore.MockStore{Store: s}},
		client, &kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
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
		op, err := New(&mockstore.Provider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
			edv.NewMockEDVClient("test", nil),
			&kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
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
		op, err := New(&mockstore.Provider{Store: &mockstore.MockStore{Store: s}},
			edv.NewMockEDVClient("test", nil),
			&kmsmock.CloseableKMS{}, &vdrimock.MockVDRIRegistry{}, "localhost:8080")
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
	const mode = "issuer"

	client := edv.NewMockEDVClient("test", nil)
	op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{}, "localhost:8080")
	require.NoError(t, err)

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
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{ID: "did1",
				Authentication: []did.VerificationMethod{{PublicKey: did.PublicKey{ID: "did1#key1"}}}}},
			"localhost:8080")
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
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{ResolveValue: &did.Doc{ID: "did1"}},
			"localhost:8080")
		require.NoError(t, err)

		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfileWithDID)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "can't find public key in DID", rr.Body.String())
	})

	t.Run("test failed to resolve did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{ResolveErr: fmt.Errorf("resolve error")},
			"localhost:8080")
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
		require.Equal(t, rr.Body.String(), "Failed to write response for invalid request received")
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
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
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
		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{CreateErr: fmt.Errorf("create did error")}, "localhost:8080")
		require.NoError(t, err)
		createProfileHandler = getHandler(t, op, createProfileEndpoint, mode)
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "create did error")
	})
}

func TestBuildSideTreeRequest(t *testing.T) {
	r, err := buildSideTreeRequest(nil)

	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestGetProfileHandler(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil)
	op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{}, "localhost:8080")
	require.NoError(t, err)

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

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("store vc err while creating the document", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), errVaultNotFound.Error())
	})
	t.Run("store vc err vault not found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), "vault not found")
	})
	t.Run("store vc err missing profile name", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
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

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
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
	t.Run("store vc invalid UUID", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequestWithInvalidUUID)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf("%s: %s", invalidUUIDErrMsg, "invalid UUID length: 19"), rr.Body.String())
	})
}

func TestRetrieveVCHandler(t *testing.T) {
	t.Run("retrieve vc success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", []byte(testStructuredDocument))

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		profile := getTestProfile()

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", profile.Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, r)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, `"Hello World!"`, rr.Body.String())
	})
	t.Run("retrieve vc error when missing profile name", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
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

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		profile := getTestProfile()

		rr := httptest.NewRecorder()
		q := req.URL.Query()
		q.Add("profile", profile.Name)
		req.URL.RawQuery = q.Encode()
		op.retrieveVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing verifiable credential ID")
	})
	t.Run("retrieve vc error when no document is found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		profile := getTestProfile()

		q := req.URL.Query()
		q.Add("id", testUUID)
		q.Add("profile", profile.Name)
		req.URL.RawQuery = q.Encode()

		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, rr.Body.String(), errDocumentNotFound.Error())
	})
	t.Run("retrieve vc unmarshal structured document error", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil)

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		profile := getTestProfile()

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", profile.Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, r)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("retrieve vc fail when writing document retrieval success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", []byte(testStructuredDocument))

		var logContents bytes.Buffer
		log.SetOutput(&logContents)

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		retrieveVCHandler := getHandler(t, op, retrieveCredentialEndpoint, "issuer")

		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := req.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", "test")
		req.URL.RawQuery = q.Encode()

		rw := mockResponseWriter{}
		retrieveVCHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, logContents.String(),
			"Failed to write response for document retrieval success: response writer failed")
	})
	t.Run("retrieve vc invalid uuid", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", []byte(testStructuredDocument))

		op, err := New(memstore.NewProvider(), client, &kmsmock.CloseableKMS{},
			&vdrimock.MockVDRIRegistry{}, "localhost:8080")
		require.NoError(t, err)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		profile := getTestProfile()

		q := r.URL.Query()
		q.Add("id", "NotAValidUUID")
		q.Add("profile", profile.Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveVCHandler(rr, r)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, `the UUID in the VC ID was not in a valid format: invalid UUID length: 13`, rr.Body.String())
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
	op, err := New(
		memstore.NewProvider(),
		edv.NewMockEDVClient("test", nil),
		&kmsmock.CloseableKMS{},
		&vdrimock.MockVDRIRegistry{},
		"localhost:8080")
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
func (c *TestClient) CreateDocument(vaultID string, document *operation.StructuredDocument) (string, error) {
	return "", errVaultNotFound
}

// RetrieveDocument sends the Mock EDV server a request to retrieve the specified document.
func (c *TestClient) ReadDocument(vaultID, docID string) ([]byte, error) {
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
