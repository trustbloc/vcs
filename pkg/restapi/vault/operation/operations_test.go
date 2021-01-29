/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mocks "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/internal/common/support"
	"github.com/trustbloc/edge-service/pkg/restapi/model"
	. "github.com/trustbloc/edge-service/pkg/restapi/vault/operation"
)

func TestNew(t *testing.T) {
	op, err := New(&Config{})
	require.NoError(t, err)
	require.NotNil(t, op)
}

func TestCreateVault(t *testing.T) {
	const path = "/vaults"

	t.Run("Internal error", func(t *testing.T) {
		kms := &mocks.KeyManager{CreateKeyErr: errors.New("test")}

		operation, err := New(&Config{
			LocalKMS: kms,
		})

		require.NoError(t, err)

		h := handlerLookup(t, operation, CreateVaultPath, http.MethodPost)

		respBody, code := sendRequestToHandler(t, h, nil, path)

		require.Equal(t, http.StatusInternalServerError, code)

		var errResp *model.ErrorResponse

		require.NoError(t, json.NewDecoder(respBody).Decode(&errResp))
		require.NotEmpty(t, errResp.Message)
	})

	t.Run("Create vault", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0b9em5ioud57602s7og")
			w.Header().Set("X-ROOTCAPABILITY", "H4sIAAAAAAAA_5SSS3OjOBSF_8vt5ZAY8AOs1fiBE-LYhEDHga4ul4wULF4ikrAhqfz3KcdxL2bVWfFRdW4d3XPuO_yb8ErRVgGCvVK1RL3esc_INRdpT9KkEUx1vYMJGjACCHp5KXs57aTigspeou_GtBwy3pChNdJNafH0JK0OPKcCEBBGUE479DZa5a951ZGsiukofn1e3ziHLAof2mP5822SvwWGdT-5C5tIrnzZiR_fHQANcFHwIyWTRDFeAfoFiaBY0SXtQAPa1lyoM0uWVqDBgQr2cvo_ClyDBk31BQkv60bR1WT2R3VmWiWiqxVoQOiFmppgRZ350wzXeMcKpj7tsLx8vJqe3CTFxSf-PueT4NMzQyxSqgC9gzv_63jDrqaAoBEVykuJLnr40KAWnL8A-vX-tfypM1M3jSvduOobodFHAwMZ5rU1tAf20DTMf3QT6TpokB0lIKDd3X53kzCP3S1i5zH0A1e6pWuuZ-4oLhcyMX9Kt1x3-NlnXiFZlEW6Wxjj62ujHOZr7Ja7m2c7nT4MNvOGL5WzXSuRkg2RwTLbhtvcC3dzj-I9JtvNON0_tYNVvFkEzzOGsXf3ZlnjdExuX9vofvCoT3zQoOJVclr3celOR0VQzLb2yH1alF5nK8uyjiz37JSNkix4HQ-UT62t8l8qZ8mUzGpxu7ufBk5ylbrjjdVv4sWSvFQ0cpxFNDpOxQS-MntoRM3lySf50-OcFjT9rAk0UOfQHWIOh8Y4YGmFVSOoqRv25UrYudMVVXtO_nf8h9u970dtsG-btj9VEZkZ94_TDV-bmd1ZflyZ093DNMOxPaA_vjsAH78__gsAAP__CIjUdMsDAAA=") // nolint: lll

			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write([]byte(`{"@context":"https://w3id.org/security/v2","id":"urn:uuid:293817e5-3a47-4685-9bd3-51eba3d5e928","invoker":"did:key:z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr#z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr","parentCapability":"urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14","allowedAction":["read","write"],"invocationTarget":{"ID":"DWPPbEVn1afJY4We3kpQmq","Type":"urn:edv:vault"},"proof":[{"capabilityChain":["urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14"],"created":"2021-01-31T13:41:13.863452194+02:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..NfznOmAi16H7fXJ1lI3-JzzHlOMopAhdGnBaF_FYK_F5BHbJMpH0u1aZ_JMgrG2XHUFMLNCBxG91DA-tJn2gDQ","nonce":"ZjtzLnBIpSNLteskV4bgTI8LOwrqrETpDI31qPglCNT_V-78ZmChHhqksMEu59WhkA_hofadF8saneziAhCDRA","proofPurpose":"capabilityDelegation","type":"Ed25519Signature2018","verificationMethod":"did:key:z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn#z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn"}]}`)) // nolint: lll
			require.NoError(t, err)
		}))

		operation, err := New(&Config{
			RemoteKMSURL: remoteKMS.URL,
			EDVURL:       edv.URL,
			LocalKMS:     &mocks.KeyManager{},
			HTTPClient:   &http.Client{},
		})
		require.NoError(t, err)

		h := handlerLookup(t, operation, CreateVaultPath, http.MethodPost)

		respBody, code := sendRequestToHandler(t, h, strings.NewReader("{}"), path)

		require.Equal(t, http.StatusCreated, code)

		var resp *vault.CreatedVault

		require.NoError(t, json.NewDecoder(respBody).Decode(&resp))

		require.NotEmpty(t, resp.ID)
		require.NotEmpty(t, resp.EDV.URI)
		require.NotEmpty(t, resp.EDV.ZCAP)
		require.NotEmpty(t, resp.KMS.URI)
		require.NotEmpty(t, resp.KMS.ZCAP)
	})
}

func TestSaveDoc(t *testing.T) {
	const path = "/vaults/vaultID1/docs"

	operation, err := New(&Config{})
	require.NoError(t, err)

	h := handlerLookup(t, operation, SaveDocPath, http.MethodPost)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusCreated, code)
}

func TestGetDocMetadata(t *testing.T) {
	const path = "/vaults/vaultID1/docs/docID1/metadata"

	operation, err := New(&Config{})
	require.NoError(t, err)

	h := handlerLookup(t, operation, GetDocMetadataPath, http.MethodGet)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

func TestCreateAuthorization(t *testing.T) {
	const path = "/vaults/vaultID1/authorizations"

	operation, err := New(&Config{})
	require.NoError(t, err)

	h := handlerLookup(t, operation, CreateAuthorizationPath, http.MethodPost)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusCreated, code)
}

func TestGetAuthorization(t *testing.T) {
	const path = "/vaults/vaultID1/authorizations/authID1"

	operation, err := New(&Config{})
	require.NoError(t, err)

	h := handlerLookup(t, operation, GetAuthorizationPath, http.MethodGet)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

func TestDeleteVault(t *testing.T) {
	const path = "/vaults/vaultID1"

	operation, err := New(&Config{})
	require.NoError(t, err)

	h := handlerLookup(t, operation, DeleteVaultPath, http.MethodDelete)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

func TestWriteResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	(&Operation{}).WriteResponse(rec, make(chan int), http.StatusInternalServerError)
	reader := rec.Result().Body

	res, err := ioutil.ReadAll(reader)
	require.NoError(t, reader.Close())
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestDeleteAuthorization(t *testing.T) {
	const path = "/vaults/vaultID1/authorizations/authID1"

	operation, err := New(&Config{})
	require.NoError(t, err)

	h := handlerLookup(t, operation, DeleteAuthorizationPath, http.MethodDelete)
	_, code := sendRequestToHandler(t, h, nil, path)

	require.Equal(t, http.StatusOK, code)
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(t *testing.T, h support.Handler, reqBody io.Reader, path string) (*bytes.Buffer, int) {
	// prepare request
	req, err := http.NewRequest(h.Method(), path, reqBody)
	require.NoError(t, err)

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(h.Path(), h.Handle()).Methods(h.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code
}

func handlerLookup(t *testing.T, op *Operation, lookup, method string) rest.Handler {
	t.Helper()

	for _, h := range op.GetRESTHandlers() {
		if h.Path() == lookup && h.Method() == method {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
