/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/utils/retry"
	edvclient "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
	"github.com/trustbloc/edge-service/pkg/internal/mock/edv"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const (
	challenge = "challenge"
	domain    = "domain"

	// json keys for compose issue credential options
	keyID   = "kid"
	purpose = "proofPurpose"
	created = "created"

	validContext = `"@context":["https://www.w3.org/2018/credentials/v1"]`

	testUUID = "4aae6b86-8e42-4d14-8cf5-21772ccb24aa"

	testURLQueryID = "http://test.com/" + testUUID

	testIssuerProfileID = "issuer"

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
          "id": "https://example.gov/status/24#94567",
          "type": "RevocationList2020Status",
          "revocationListIndex": "94567",
          "revocationListCredential": "https://example.gov/status/24"
      }
	}`

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

	testStructuredVCDocument = `{
	   "id":"someID",
	   "meta":{
		  "created":"2019-06-18"
	   },
	   "content":{
		  "message":%s
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
)

var mockLoggerProvider = mocklogger.Provider{MockLogger: &mocklogger.MockLogger{}} //nolint: gochecknoglobals

// errVaultNotFound throws an error when vault is not found
var errVaultNotFound = errors.New("vault not found")

// errDocumentNotFound throws an error when document associated with ID is not found
var errDocumentNotFound = errors.New("edv does not have a document associated with ID")

func TestMain(m *testing.M) {
	log.Initialize(&mockLoggerProvider)

	log.SetLevel(logModuleName, log.DEBUG)

	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	t.Run("test error from opening credential store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
		op, err := New(&Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error open store"),
			},
			EDVClient: client, VDRI: &vdrmock.MockVDRegistry{}, HostURL: "localhost:8080",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error open store")
		require.Nil(t, op)
	})
	t.Run("fail to create credential store", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
		op, err := New(&Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("create error"),
			}, EDVClient: client, VDRI: &vdrmock.MockVDRegistry{},
			HostURL: "localhost:8080",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create error")
		require.Nil(t, op)
	})
	t.Run("test error from csl", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
		op, err := New(&Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{FailNamespace: "credentialstatus"},
			EDVClient:     client, VDRI: &vdrmock.MockVDRegistry{}, HostURL: "localhost:8080",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to instantiate new csl status")
		require.Nil(t, op)
	})
}

func TestUpdateCredentialStatusHandler(t *testing.T) {
	const profileID = "example_university"

	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
	s := make(map[string]ariesmockstorage.DBEntry)
	s["profile_issuer_example_university"] = ariesmockstorage.DBEntry{Value: []byte(testIssuerProfile)}
	s["profile_issuer_vc_without_status"] = ariesmockstorage.DBEntry{Value: []byte(testIssuerProfileWithDisableVCStatus)}
	s["profile_issuer_empty"] = ariesmockstorage.DBEntry{Value: []byte("{}")}

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider: &ariesmockstorage.MockStoreProvider{
			Store: &ariesmockstorage.MockStore{Store: s},
		},
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		KeyManager:         customKMS,
		Crypto:             customCrypto,
		VDRI:               &vdrmock.MockVDRegistry{},
		HostURL:            "localhost:8080",
		RetryParameters:    &retry.Params{},
		DocumentLoader:     createTestDocumentLoader(t),
	})
	require.NoError(t, err)

	updateCredentialStatusHandler := getHandler(t, op, updateCredentialStatusEndpoint, http.MethodPost)

	t.Run("update credential status success", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		setMockEDVClientReadDocumentReturnValue(t, client, op, fmt.Sprintf(testStructuredVCDocument, validVC),
			fmt.Sprintf(testStructuredVCDocument, validVC))

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   cslstatus.RevocationList2020Status,
				Status: "1",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test disable vc status", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		setMockEDVClientReadDocumentReturnValue(t, client, op,
			fmt.Sprintf(testStructuredVCDocument, validVCWithoutStatus),
			fmt.Sprintf(testStructuredVCDocument, validVCWithoutStatus))

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   cslstatus.RevocationList2020Status,
				Status: "1",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = "vc_without_status"

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "vc status is disabled for profile")
	})

	t.Run("test error decode request", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, []byte("w"),
			urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to decode request received")
	})

	t.Run("test error from parse credential", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		setMockEDVClientReadDocumentReturnValue(t, client, op, fmt.Sprintf(testStructuredVCDocument, invalidVC),
			fmt.Sprintf(testStructuredVCDocument, invalidVC))

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   cslstatus.RevocationList2020Status,
				Status: "1",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse credentia")
	})

	t.Run("test error from get profile", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = "wrongProfile"

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, []byte("w"),
			urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid issuer profile")
	})

	t.Run("test error from update vc status", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{updateVCErr: fmt.Errorf("failed to update")}
		op.edvClient = client

		setMockEDVClientReadDocumentReturnValue(t, client, op, fmt.Sprintf(testStructuredVCDocument, validVC),
			fmt.Sprintf(testStructuredVCDocument, validVC))

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   cslstatus.RevocationList2020Status,
				Status: "1",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to update vc status")
	})

	t.Run("test error from update vc status wrong type", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		setMockEDVClientReadDocumentReturnValue(t, client, op, fmt.Sprintf(testStructuredVCDocument, validVC),
			fmt.Sprintf(testStructuredVCDocument, validVC))

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   "wrongType",
				Status: "1",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "credential status wrongType not supported")
	})

	t.Run("test error get credential", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = &edv.Client{ReadDocumentError: fmt.Errorf("failed to read")}

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   cslstatus.RevocationList2020Status,
				Status: "1",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "no VC under profile")
	})

	t.Run("test error parse cred status", func(t *testing.T) {
		op.vcStatusManager = &mockVCStatusManager{}
		op.edvClient = client

		setMockEDVClientReadDocumentReturnValue(t, client, op, fmt.Sprintf(testStructuredVCDocument, validVC),
			fmt.Sprintf(testStructuredVCDocument, validVC))

		ucsReq := UpdateCredentialStatusRequest{CredentialID: "http://example.edu/credentials/1872",
			CredentialStatus: CredentialStatus{
				Type:   cslstatus.RevocationList2020Status,
				Status: "wrong",
			}}
		ucsReqBytes, err := json.Marshal(ucsReq)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[profileIDPathParam] = profileID

		rr := serveHTTPMux(t, updateCredentialStatusHandler, updateCredentialStatusEndpoint, ucsReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to parse status")
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

type mockAuthService struct {
	createDIDKeyFunc func() (string, error)
	signHeaderFunc   func(req *http.Request, capability []byte,
		verificationMethod string) (*http.Header, error)
}

func (m *mockAuthService) CreateDIDKey() (string, error) {
	if m.createDIDKeyFunc != nil {
		return m.createDIDKeyFunc()
	}

	return "", nil
}

func (m *mockAuthService) SignHeader(req *http.Request, capability []byte,
	verificationMethod string) (*http.Header, error) {
	if m.signHeaderFunc != nil {
		return m.signHeaderFunc(req, capability, verificationMethod)
	}

	return nil, nil
}

func TestCreateProfileHandler(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		EDVClient:          client,
		KeyManager:         customKMS,
		VDRI:               &vdrmock.MockVDRegistry{},
		Crypto:             customCrypto,
		HostURL:            "localhost:8080", Domain: "testnet",
	})
	require.NoError(t, err)

	op.commonDID = &mockCommonDID{}
	op.authService = &mockAuthService{}

	createProfileHandler := getHandler(t, op, createProfileEndpoint, http.MethodPost)

	t.Run("failed to create did key", func(t *testing.T) {
		op.authService = &mockAuthService{createDIDKeyFunc: func() (string, error) {
			return "", fmt.Errorf("failed to create did key")
		}}

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create did key")
	})

	t.Run("failed to create vault", func(t *testing.T) {
		op.authService = &mockAuthService{}
		op.edvClient = edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, fmt.Errorf("failed to create vault"))
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "fail to create vault in EDV")
	})

	t.Run("create profile success", func(t *testing.T) {
		op.authService = &mockAuthService{}
		op.edvClient = edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(testIssuerProfile)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		profile := vcprofile.IssuerProfile{}

		err = json.Unmarshal(rr.Body.Bytes(), &profile)

		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.Name)
		require.Contains(t, profile.URI, "https://example.com/credentials")
	})

	t.Run("create profile - profile already exists", func(t *testing.T) {
		op.authService = &mockAuthService{}
		vReqBytes, err := json.Marshal(getTestProfile())
		require.NoError(t, err)

		rr := serveHTTP(t, createProfileHandler.Handle(), http.MethodPost, createProfileEndpoint, vReqBytes)
		require.Equal(t, http.StatusCreated, rr.Code)

		rr = serveHTTP(t, createProfileHandler.Handle(), http.MethodPost, createProfileEndpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "profile test already exists")
	})

	t.Run("create profile - other error in GetProfile", func(t *testing.T) {
		s := &ariesmockstorage.MockStore{
			Store: make(map[string]ariesmockstorage.DBEntry),
		}

		op, err := New(&Config{
			StoreProvider:      &ariesmockstorage.MockStoreProvider{Store: s},
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			Crypto:             customCrypto,
			HostURL:            "localhost:8080", Domain: "testnet",
		})
		require.NoError(t, err)

		s.ErrGet = errors.New("get error")

		op.commonDID = &mockCommonDID{}

		createProfileHandler = getHandler(t, op, createProfileEndpoint, http.MethodPost)

		vReqBytes, err := json.Marshal(getTestProfile())
		require.NoError(t, err)

		rr := serveHTTP(t, createProfileHandler.Handle(), http.MethodPost, createProfileEndpoint, vReqBytes)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "get error")
	})

	t.Run("create profile success without creating did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client, KeyManager: customKMS,
			VDRI: &vdrmock.MockVDRegistry{ResolveValue: &did.Doc{
				ID:             "did1",
				Authentication: []did.Verification{{VerificationMethod: did.VerificationMethod{ID: "did1#key1"}}},
			}},
			HostURL: "localhost:8080",
		})

		require.NoError(t, err)

		createProfileHandler = getHandler(t, op, createProfileEndpoint, http.MethodPost)

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		issuerProfileWithDID := strings.Replace(testIssuerProfileWithDID, "\"key\",",
			"\""+base58.Encode(priv.Seed())+"\",", 1)
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint,
			bytes.NewBuffer([]byte(issuerProfileWithDID)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		profile := vcprofile.IssuerProfile{}

		err = json.Unmarshal(rr.Body.Bytes(), &profile)
		require.NoError(t, err)

		require.Equal(t, http.StatusCreated, rr.Code)
		require.NotEmpty(t, profile.Name)
		require.Contains(t, profile.URI, "https://example.com/credentials")
		require.Equal(t, "did1#key1", profile.Creator)
	})

	t.Run("test failed to resolve did", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client, KeyManager: customKMS,
			VDRI:    &vdrmock.MockVDRegistry{ResolveErr: fmt.Errorf("resolve error")},
			HostURL: "localhost:8080",
		})

		require.NoError(t, err)

		createProfileHandler = getHandler(t, op, createProfileEndpoint, http.MethodPost)

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

		errResp := &model.ErrorResponse{}
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

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, invalidRequestErrMsg+": EOF", errResp.Message)
	})
	t.Run("create profile error - unable to create vault in EDV", func(t *testing.T) {
		errTest := errors.New("error in create EDV vault")
		client := edv.NewMockEDVClient("test", nil,
			nil, []string{"testID"}, errTest)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			Crypto:             customCrypto,
			HostURL:            "localhost:8080", Domain: "testnet",
		})
		require.NoError(t, err)

		op.commonDID = &mockCommonDID{}

		createProfileHandler = getHandler(t, op, createProfileEndpoint, http.MethodPost)

		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		createProfileHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("create profile error unable to write a response while reading the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte("")))
		require.NoError(t, err)
		rw := mockResponseWriter{}
		createProfileHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			"Unable to send error message, response writer failed")
	})
}

func TestGetProfileHandler(t *testing.T) {
	client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		Crypto:             customCrypto,
		EDVClient:          client,
		KeyManager:         customKMS,
		VDRI:               &vdrmock.MockVDRegistry{},
		HostURL:            "localhost:8080",
	})

	require.NoError(t, err)

	op.commonDID = &mockCommonDID{}

	getProfileHandler := getHandler(t, op, getProfileEndpoint, http.MethodGet)

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
		profileResponse := &vcprofile.IssuerProfile{}
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

func TestDeleteProfileHandler(t *testing.T) {
	edvClient := edv.NewMockEDVClient("test", nil, nil, nil, nil)
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		EDVClient:          edvClient,
		KeyManager:         customKMS,
		VDRI:               &vdrmock.MockVDRegistry{},
		Crypto:             customCrypto,
		HostURL:            "localhost:8080", Domain: "testnet",
	})
	require.NoError(t, err)

	op.commonDID = &mockCommonDID{}

	handler := getHandler(t, op, deleteProfileEndpoint, http.MethodDelete)

	urlVars := make(map[string]string)
	urlVars["id"] = testIssuerProfileID

	t.Run("delete profile - success", func(t *testing.T) {
		saveTestProfile(t, op, getIssuerProfile())

		rr := serveHTTPMux(t, handler, deleteProfileEndpoint, nil, urlVars)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("delete profile - other error in delete profile from store", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: &ariesmockstorage.MockStoreProvider{Store: &ariesmockstorage.MockStore{
				Store:     make(map[string]ariesmockstorage.DBEntry),
				ErrDelete: errors.New("delete error"),
			}},
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			EDVClient:          edvClient,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			Crypto:             customCrypto,
			HostURL:            "localhost:8080", Domain: "testnet",
		})
		require.NoError(t, err)

		op.commonDID = &mockCommonDID{}

		handler := getHandler(t, op, deleteProfileEndpoint, http.MethodDelete)

		saveTestProfile(t, op, getIssuerProfile())
		rr := serveHTTPMux(t, handler, deleteProfileEndpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "delete error")
	})
}

func createProfileSuccess(t *testing.T, op *Operation) *vcprofile.IssuerProfile {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, createProfileEndpoint, bytes.NewBuffer([]byte(testIssuerProfile)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createProfileEndpoint := getHandler(t, op, createProfileEndpoint, http.MethodPost)
	createProfileEndpoint.Handle().ServeHTTP(rr, req)

	profile := &vcprofile.IssuerProfile{}

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

func (m failingCrypto) WrapKey(cek []byte, apu []byte, apv []byte,
	recPubKey *cryptoapi.PublicKey, opts ...cryptoapi.WrapKeyOpts) (*cryptoapi.RecipientWrappedKey, error) {
	panic("implement me")
}

func (m failingCrypto) UnwrapKey(recWK *cryptoapi.RecipientWrappedKey, kh interface{},
	opts ...cryptoapi.WrapKeyOpts) ([]byte, error) {
	panic("implement me")
}

func (m failingCrypto) SignMulti(messages [][]byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (m failingCrypto) VerifyMulti(messages [][]byte, signature []byte, kh interface{}) error {
	panic("implement me")
}

func (m failingCrypto) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, kh interface{}) error {
	panic("implement me")
}

func (m failingCrypto) DeriveProof(messages [][]byte, bbsSignature []byte, nonce []byte,
	revealedIndexes []int, kh interface{}) ([]byte, error) {
	panic("implement me")
}

type failingJWEEncrypt struct {
	encryptReturnValue *jose.JSONWebEncryption
	errEncrypt         error
}

func (f *failingJWEEncrypt) EncryptWithAuthData(_, _ []byte) (*jose.JSONWebEncryption, error) {
	panic("implement me")
}

func (f *failingJWEEncrypt) Encrypt(_ []byte) (*jose.JSONWebEncryption, error) {
	return f.encryptReturnValue, f.errEncrypt
}

func TestStoreVCHandler(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	loader := createTestDocumentLoader(t)

	t.Run("store vc success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getIssuerProfile())

		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("store vc err while creating the document - vault not found", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getIssuerProfile())

		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errResp.Message, errVaultNotFound.Error())
	})
	t.Run("store vc err missing profile name", func(t *testing.T) {
		client := NewMockEDVClient("test")

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreIncorrectCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errResp.Message, "missing profile name")
	})
	t.Run("store vc err unable to unmarshal vc", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequestBadVC)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, "unable to unmarshal the VC: decode new credential: "+
			"embedded proof is not JSON: unexpected end of JSON input", errResp.Message)
	})
	t.Run("store vc err while computing MAC", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})

		op.macCrypto = failingCrypto{}
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		require.Equal(t, "i always fail", errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("store vc err while encrypting structured doc", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})

		testError := errors.New("test encryption failure")

		op.jweEncrypter = &failingJWEEncrypt{errEncrypt: testError}

		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		require.Equal(t, testError.Error(), errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("store vc err while serializing JWE", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})

		op.jweEncrypter = &failingJWEEncrypt{encryptReturnValue: &jose.JSONWebEncryption{}}

		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, storeCredentialEndpoint,
			bytes.NewBuffer([]byte(testStoreCredentialRequest)))
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		op.storeCredentialHandler(rr, req)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		require.Equal(t, "ciphertext cannot be empty", errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestRetrieveVCHandler(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	loader := createTestDocumentLoader(t)

	t.Run("retrieve vc success", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1, testStructuredDocument1)

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
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID1", "testID2"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1, testStructuredDocument1)

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
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID1", "testID2"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1, testStructuredDocument2)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)

		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, errMultipleInconsistentVCsFoundForOneID.Error(), errResp.Message)

		require.Equal(t, http.StatusConflict, rr.Code)
	})
	t.Run("retrieve vc fail - no VC found under the given ID", func(t *testing.T) {
		// The mock client needs to be passed into operation.New, but we need the packer and key from the
		// operation object in order to create a decryptable EncryptedDocument to be returned from the mock EDV client.
		// It's set to nil here but later in this test it gets set to a valid object.
		client := edv.NewMockEDVClient("test", nil, nil, nil, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1, testStructuredDocument1)

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, `no VC under profile "test" was found with the given id`, errResp.Message)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("retrieve vc error when missing profile name", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
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
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
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

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			EDVClient:          client,
			Crypto:             customCrypto,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

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
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

		setMockEDVClientReadDocumentReturnValue(t, client, op, testStructuredDocument1, testStructuredDocument1)

		retrieveVCHandler := getHandler(t, op, retrieveCredentialEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := req.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		req.URL.RawQuery = q.Encode()

		rw := mockResponseWriter{}
		retrieveVCHandler.Handle().ServeHTTP(rw, req)
		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			"Failed to write response for document retrieval success: response writer failed")
	})
	t.Run("fail to compute MAC when querying vault", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

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
		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, `i always fail`,
			errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("fail to deserialize JWE", func(t *testing.T) {
		client := edv.NewMockEDVClient("test",
			&models.EncryptedDocument{JWE: []byte("{ not valid JWE }")},
			nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			RetryParameters:    &retry.Params{},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		saveTestProfile(t, op, getTestProfile())

		r, err := http.NewRequest(http.MethodGet, retrieveCredentialEndpoint,
			bytes.NewBuffer([]byte(nil)))
		require.NoError(t, err)

		q := r.URL.Query()
		q.Add("id", testURLQueryID)
		q.Add("profile", getTestProfile().Name)
		r.URL.RawQuery = q.Encode()
		rr := httptest.NewRecorder()

		op.retrieveCredentialHandler(rr, r)
		errResp := &model.ErrorResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)

		require.Equal(t, "invalid character 'n' looking for beginning of object key string", errResp.Message)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestVCStatus(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	loader := createTestDocumentLoader(t)

	t.Run("test error from get CSL", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			EDVClient:          client,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{GetRevocationListVCErr: fmt.Errorf("error get csl")}

		vcStatusHandler := getHandler(t, op, credentialStatusEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, credentialStatus+"/1", nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		vcStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "error get csl")
	})

	t.Run("test success", func(t *testing.T) {
		client := edv.NewMockEDVClient("test", nil, nil, []string{"testID"}, nil)

		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			EDVClient:          client,
			Crypto:             customCrypto,
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{},
			HostURL:            "localhost:8080",
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{
			getRevocationListVCValue: []byte(`{"k1":"v1"}`),
		}

		vcStatusHandler := getHandler(t, op, credentialStatusEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, credentialStatus+"/1", nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()

		vcStatusHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		require.Equal(t, `{"k1":"v1"}`, rr.Body.String())
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
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	op, err := New(&Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		Crypto:             customCrypto,
		EDVClient: edv.NewMockEDVClient("test",
			nil, nil, []string{"testID"}, nil),
		KeyManager:     customKMS,
		VDRI:           &vdrmock.MockVDRegistry{},
		HostURL:        "localhost:8080",
		DocumentLoader: createTestDocumentLoader(t),
	})

	require.NoError(t, err)

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestIssueCredential(t *testing.T) {
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	keyID, pubKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	endpoint := "/test/credentials/issue"
	issuerProfileDIDKey := "did:test:abc#" + keyID
	profile := getTestProfile()
	profile.Creator = issuerProfileDIDKey

	loader := createTestDocumentLoader(t)

	op, err := New(&Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		KeyManager:         customKMS,
		Crypto:             customCrypto,
		VDRI: &vdrmock.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, pubKey)}, nil
			},
		},
		DocumentLoader: loader,
	})
	require.NoError(t, err)

	err = op.profileStore.SaveProfile(profile)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = profile.Name

	handler := getHandler(t, op, issueCredentialPath, http.MethodPost)

	t.Run("issue credential - success", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, pubKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		ops.vcStatusManager = &mockVCStatusManager{createStatusIDValue: &verifiable.TypedID{ID: "id"}}

		profile.SignatureRepresentation = verifiable.SignatureJWS
		profile.SignatureType = vccrypto.JSONWebSignature2020

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, http.MethodPost)

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
				CredentialStatus: CredentialStatusOpt{
					Type: cslstatus.RevocationList2020Status,
				},
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
		require.Equal(t, "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
			signedVCResp["@context"].([]interface{})[2])
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

		ops, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, pubKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		profile.SignatureRepresentation = verifiable.SignatureJWS
		profile.SignatureType = vccrypto.Ed25519Signature2018

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, http.MethodPost)

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

		ops, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, pubKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		profile.SignatureRepresentation = verifiable.SignatureJWS

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, http.MethodPost)

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

	t.Run("issue credential with opts - invalid vc status", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, pubKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		profile.SignatureRepresentation = verifiable.SignatureJWS

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, http.MethodPost)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts: &IssueCredentialOptions{
				CredentialStatus: CredentialStatusOpt{Type: "wrong"},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueCredentialHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "not supported credential status type")
	})

	t.Run("issue credential - invalid profile", func(t *testing.T) {
		ops, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			Crypto:             customCrypto,
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, ops, issueCredentialPath, http.MethodPost)

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
		vc, err := verifiable.ParseCredential([]byte(validVC), verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
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
		op1, err := New(&Config{
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, keyID, pubKey)}, nil
				},
			},
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		issueHandler := getHandler(t, op1, issueCredentialPath, http.MethodPost)

		req := &IssueCredentialRequest{
			Credential: []byte(validVC),
			Opts:       &IssueCredentialOptions{AssertionMethod: "did:test:urosdjwas7823y#key-1"},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, issueHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "data not found")
	})

	t.Run("issue credential - add credential status error", func(t *testing.T) {
		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", pubKey)

		op, err := New(&Config{
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		op.vcStatusManager = &mockCredentialStatusManager{CreateErr: errors.New("csl error")}

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, http.MethodPost)

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
		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", pubKey)

		op, err := New(&Config{
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, http.MethodPost)

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
		didDoc := createDIDDoc("did:test:hd9712akdsaishda7", pubKey)

		op, err := New(&Config{
			Crypto:             &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign credential")},
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI:               &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{createStatusIDValue: &verifiable.TypedID{ID: "id"}}

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		issueCredentialHandler := getHandler(t, op, issueCredentialPath, http.MethodPost)

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
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	key1ID, pubKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

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
	degreeType := "UniversityDegreeCredential"
	types := []string{"VerifiableCredential", degreeType}
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
	evidence["type"] = "IssuerPolicy"
	evidence["verifier"] = evidenceVerifier
	evidence[customField] = customFieldVal

	loader := createTestDocumentLoader(t)

	op, err := New(&Config{
		StoreProvider:      ariesmemstorage.NewProvider(),
		KMSSecretsProvider: ariesmemstorage.NewProvider(),
		KeyManager:         customKMS,
		VDRI:               &vdrmock.MockVDRegistry{},
		Crypto:             &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign credential")},
		DocumentLoader:     loader,
	})
	require.NoError(t, err)

	op.vcStatusManager = &mockVCStatusManager{createStatusIDValue: &verifiable.TypedID{ID: uuid.New().URN()}}

	handler := getHandler(t, op, composeAndIssueCredentialPath, http.MethodPost)

	endpoint := "/test/credentials/composeAndIssueCredential"
	issuerProfileDIDKey := "did:test:abc#" + key1ID
	profile := getTestProfile()
	profile.Creator = issuerProfileDIDKey

	err = op.profileStore.SaveProfile(profile)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = profile.Name

	t.Run("compose and issue credential - success", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, key1ID, pubKey)}, nil
				},
			},
			Crypto:         customCrypto,
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		op.vcStatusManager = &mockVCStatusManager{createStatusIDValue: &verifiable.TypedID{
			ID:   uuid.New().URN(),
			Type: "RevocationList2020Status", CustomFields: verifiable.CustomFields{
				"revocationListIndex":      "94567",
				"revocationListCredential": "https://example.com/credentials/status/3",
			},
		}}

		err = op.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		restHandler := getHandler(t, op, composeAndIssueCredentialPath, http.MethodPost)

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
			Evidence:       evidenceJSON,
			TermsOfUse:     termsOfUseJSON,
			CredentialFormatOptions: json.RawMessage([]byte(`
				{
				"@context": [
					"https://www.w3.org/2018/credentials/v1", 
					"https://www.w3.org/2018/credentials/examples/v1"
					]
				}
			`)),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		// invoke the endpoint
		rr := serveHTTPMux(t, restHandler, endpoint, reqBytes, urlVars)
		require.Equal(t, http.StatusCreated, rr.Code)

		// validate the response
		vcResp, err := verifiable.ParseCredential(rr.Body.Bytes(), verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)

		// top level values
		require.Equal(t, issuer, vcResp.Issuer.ID)
		require.Equal(t, 2, len(vcResp.Types))
		require.Equal(t, degreeType, vcResp.Types[1])
		require.Equal(t, issueDate, vcResp.Issued.Time)
		require.Equal(t, expiryDate, vcResp.Expired.Time)
		require.NotNil(t, vcResp.Evidence)
		require.NotNil(t, issuer, vcResp.Issuer)

		// credential subject
		credSubject, ok := vcResp.Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.Equal(t, subject, credSubject[0].ID)
		require.Equal(t, name, credSubject[0].CustomFields["name"])
		require.Equal(t, customFieldVal, credSubject[0].CustomFields[customField])

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
		vcResp, err = verifiable.ParseCredential(rr.Body.Bytes(), verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.Equal(t, 1, len(vcResp.Types))
		require.Equal(t, "VerifiableCredential", vcResp.Types[0])

		credSubject, ok = vcResp.Subject.([]verifiable.Subject)
		require.True(t, ok)
		require.Equal(t, subject, credSubject[0].ID)

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
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		restHandler := getHandler(t, ops, composeAndIssueCredentialPath, http.MethodPost)

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
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			DocumentLoader:     loader,
		})
		require.NoError(t, err)

		ops.vcStatusManager = &mockCredentialStatusManager{CreateErr: errors.New("csl error")}

		err = ops.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		req := &ComposeCredentialRequest{}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		restHandler := getHandler(t, ops, composeAndIssueCredentialPath, http.MethodPost)

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

		req := &ComposeCredentialRequest{
			ProofFormat:        "invalid-proof-format-value",
			ProofFormatOptions: []byte(fmt.Sprintf(`{"kid":"did:local:abc#%s"}`, key1ID)),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		op1, err := New(&Config{
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
			VDRI: &vdrmock.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: createDIDDocWithKeyID(didID, key1ID, pubKey)}, nil
				},
			},
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = op1.profileStore.SaveProfile(profile)
		require.NoError(t, err)

		handler1 := getHandler(t, op1, composeAndIssueCredentialPath, http.MethodPost)

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
	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	t.Run("generate key pair (default)- success", func(t *testing.T) {
		op, err := New(&Config{
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
		})
		require.NoError(t, err)

		generateKeypairHandler := getHandler(t, op, generateKeypairPath, http.MethodGet)

		rr := serveHTTP(t, generateKeypairHandler.Handle(), http.MethodGet, generateKeypairPath, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		generateKeypairResp := make(map[string]interface{})

		err = json.Unmarshal(rr.Body.Bytes(), &generateKeypairResp)
		require.NoError(t, err)
		require.NotEmpty(t, generateKeypairResp["publicKey"])
	})

	t.Run("generate key pair - BBS", func(t *testing.T) {
		op, err := New(&Config{
			Crypto:             customCrypto,
			StoreProvider:      ariesmemstorage.NewProvider(),
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
		})
		require.NoError(t, err)

		generateKeypairHandler := getHandler(t, op, generateKeypairPath, http.MethodGet)

		req := &GenerateKeyPairRequest{
			KeyType: kms.BLS12381G2Type,
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, generateKeypairHandler.Handle(), http.MethodGet, generateKeypairPath, reqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		generateKeypairResp := make(map[string]interface{})

		err = json.Unmarshal(rr.Body.Bytes(), &generateKeypairResp)
		require.NoError(t, err)
		require.NotEmpty(t, generateKeypairResp["publicKey"])
	})

	t.Run("generate key pair - failure", func(t *testing.T) {
		op, err := New(&Config{
			Crypto:             customCrypto,
			KMSSecretsProvider: ariesmemstorage.NewProvider(),
			StoreProvider:      ariesmemstorage.NewProvider(),
			KeyManager:         customKMS,
		})
		require.NoError(t, err)

		op.kms = &mockkms.KeyManager{CreateKeyErr: errors.New("kms - create keyset error")}

		generateKeypairHandler := getHandler(t, op, generateKeypairPath, http.MethodGet)

		rr := serveHTTP(t, generateKeypairHandler.Handle(), http.MethodGet, generateKeypairPath, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create key pair")
	})
}

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

func getProfileRequest() *ProfileRequest {
	return &ProfileRequest{
		Name:          testIssuerProfileID,
		URI:           "http://example.com/credentials",
		SignatureType: "Ed25519Signature2018",
	}
}

func getHandler(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	t.Helper()

	return getHandlerWithError(t, op, pathToLookup, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	t.Helper()

	return handlerLookup(t, op, pathToLookup, methodToLookup)
}

func handlerLookup(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == pathToLookup && h.Method() == methodToLookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func getTestProfile() *vcprofile.IssuerProfile {
	return &vcprofile.IssuerProfile{
		DataProfile: &vcprofile.DataProfile{
			Name:          "test",
			DID:           "did:test:abc",
			SignatureType: "Ed25519Signature2018",
			Creator:       "did:test:abc#key1",
		},
		URI: "https://test.com/credentials",
	}
}

func getIssuerProfile() *vcprofile.IssuerProfile {
	return &vcprofile.IssuerProfile{
		DataProfile: &vcprofile.DataProfile{
			Name:          testIssuerProfileID,
			DID:           "did:test:abc",
			SignatureType: "Ed25519Signature2018",
			Creator:       "did:test:abc#key1",
		},
		URI: "https://example.com/credentials",
	}
}

func saveTestProfile(t *testing.T, op *Operation, profile *vcprofile.IssuerProfile) {
	t.Helper()

	err := op.profileStore.SaveProfile(profile)
	require.NoError(t, err)
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

func setMockEDVClientReadDocumentReturnValue(t *testing.T, client *edv.Client, op *Operation,
	structuredDocForFirstCall, structuredDocForSubsequentCalls string) {
	t.Helper()

	firstEncryptedDocToReturn := prepareEncryptedDocument(t, op, structuredDocForFirstCall)
	subsequentEncryptedDocToReturn := prepareEncryptedDocument(t, op, structuredDocForSubsequentCalls)

	client.ReadDocumentFirstReturnValue = &firstEncryptedDocToReturn
	client.ReadDocumentSubsequentReturnValue = &subsequentEncryptedDocToReturn
}

func prepareEncryptedDocument(t *testing.T, op *Operation, structuredDoc string) models.EncryptedDocument {
	t.Helper()

	jwe, err := op.jweEncrypter.Encrypt([]byte(structuredDoc))
	require.NoError(t, err)

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
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

type TestClient struct {
	edvServerURL string
}

// NewMockEDVClient
func NewMockEDVClient(edvServerURL string) *TestClient {
	return &TestClient{edvServerURL: edvServerURL}
}

// CreateDataVault sends the EDV server a request to create a new data vault.
func (c *TestClient) CreateDataVault(config *models.DataVaultConfiguration,
	opts ...edvclient.ReqOption) (string, []byte, error) {
	return "", nil, nil
}

// CreateDocument sends the EDV server a request to store the specified document.
func (c *TestClient) CreateDocument(vaultID string, document *models.EncryptedDocument,
	opts ...edvclient.ReqOption) (string, error) {
	return "", errVaultNotFound
}

// RetrieveDocument sends the Mock EDV server a request to retrieve the specified document.
func (c *TestClient) ReadDocument(vaultID, docID string,
	opts ...edvclient.ReqOption) (*models.EncryptedDocument, error) {
	return nil, errDocumentNotFound
}

func (c *TestClient) QueryVault(vaultID, name, value string, opts ...edvclient.ReqOption) ([]string, error) {
	return []string{"dummyID"}, nil
}

type mockVCStatusManager struct {
	createStatusIDValue      *verifiable.TypedID
	createStatusIDErr        error
	updateVCErr              error
	getRevocationListVCValue []byte
	GetRevocationListVCErr   error
}

func (m *mockVCStatusManager) CreateStatusID(profile *vcprofile.DataProfile, url string) (*verifiable.TypedID, error) {
	return m.createStatusIDValue, m.createStatusIDErr
}

func (m *mockVCStatusManager) UpdateVC(v *verifiable.Credential, profile *vcprofile.DataProfile, status bool) error {
	return m.updateVCErr
}

func (m *mockVCStatusManager) GetRevocationListVC(id string) ([]byte, error) {
	return m.getRevocationListVCValue, m.GetRevocationListVCErr
}

type mockCredentialStatusManager struct {
	CreateErr error
}

func (m *mockCredentialStatusManager) CreateStatusID(profile *vcprofile.DataProfile,
	url string) (*verifiable.TypedID, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	return nil, nil
}

func (m *mockCredentialStatusManager) UpdateVC(v *verifiable.Credential,
	profile *vcprofile.DataProfile, status bool) error {
	return nil
}

func (m *mockCredentialStatusManager) GetRevocationListVC(id string) ([]byte, error) {
	return nil, nil
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}

//go:embed testdata/lds-jws2020-v1.jsonld
var jws2020Vocab []byte //nolint:gochecknoglobals // embedded test context

func createTestDocumentLoader(t *testing.T) *jld.DocumentLoader {
	t.Helper()

	loader, err := jld.NewDocumentLoader(ariesmockstorage.NewMockStoreProvider(),
		jld.WithExtraContexts(
			jld.ContextDocument{
				URL:     "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
				Content: jws2020Vocab,
			},
		),
	)
	require.NoError(t, err)

	return loader
}
