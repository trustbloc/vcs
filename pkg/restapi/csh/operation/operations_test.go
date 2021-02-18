/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
	storage2 "github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/restapi/models"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/internal/mock/storage"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
)

func TestNew(t *testing.T) {
	t.Run("returns an instance", func(t *testing.T) {
		o, err := operation.New(config(t))
		require.NoError(t, err)
		require.NotNil(t, o)
	})

	t.Run("error when creating profile store", func(t *testing.T) {
		expected := errors.New("test")
		cfg := config(t)

		cfg.StoreProvider = &storage.MockProvider{
			Stores: map[string]storage2.Store{
				"zcap": &mockstore.MockStore{Store: make(map[string][]byte)},
			},
			CreateErrors: map[string]error{
				"profile": expected,
			},
		}

		_, err := operation.New(cfg)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("error when creating zcap store", func(t *testing.T) {
		expected := errors.New("test")
		cfg := config(t)

		cfg.StoreProvider = &storage.MockProvider{
			Stores: map[string]storage2.Store{
				"profile": &mockstore.MockStore{Store: make(map[string][]byte)},
			},
			CreateErrors: map[string]error{
				"zcap": expected,
			},
		}

		_, err := operation.New(cfg)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestOperation_GetRESTHandlers(t *testing.T) {
	o := newOp(t)
	require.True(t, len(o.GetRESTHandlers()) > 0)
}

func TestOperation_CreateProfile(t *testing.T) {
	t.Run("creates a profile", func(t *testing.T) {
		controller := fmt.Sprintf("did:example:controller#%s", uuid.New().String())
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateProfile(result, newReq(t,
			http.MethodPost,
			"/profiles",
			&openapi.Profile{
				Controller: &controller,
			},
		))
		require.Equal(t, http.StatusCreated, result.Code)
		response := &openapi.Profile{}

		err := json.NewDecoder(result.Body).Decode(response)
		require.NoError(t, err)

		require.Equal(t, controller, *response.Controller)
		require.NotEmpty(t, response.ID)
		require.NotEmpty(t, response.Zcap)
	})

	t.Run("err badrequest if controller is missing", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateProfile(result, newReq(t,
			http.MethodPost,
			"/profiles",
			&openapi.Profile{},
		))

		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "missing controller")
	})

	t.Run("err internalservererror if failed to create zcap", func(t *testing.T) {
		cfg := config(t)
		cfg.Aries.KMS = &mockkms.KeyManager{
			CreateKeyErr: errors.New("test"),
		}

		o, err := operation.New(cfg)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.CreateProfile(result, newReq(t,
			http.MethodPost,
			"/profiles",
			&openapi.Profile{Controller: controller()},
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to create zcap")
	})

	t.Run("err internalservererror if cannot store profile", func(t *testing.T) {
		cfg := config(t)
		cfg.StoreProvider = &storage.MockProvider{
			Stores: map[string]storage2.Store{
				"profile": &mockstore.MockStore{
					Store:  make(map[string][]byte),
					ErrPut: errors.New("test"),
				},
				"zcap": &mockstore.MockStore{Store: make(map[string][]byte)},
			},
		}

		o, err := operation.New(cfg)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.CreateProfile(result, newReq(t,
			http.MethodPost,
			"/profile",
			&openapi.Profile{Controller: controller()},
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to store profile")
	})

	t.Run("err internalservererror if cannot store zcap", func(t *testing.T) {
		cfg := config(t)
		cfg.StoreProvider = &storage.MockProvider{
			Stores: map[string]storage2.Store{
				"profile": &mockstore.MockStore{Store: make(map[string][]byte)},
				"zcap": &mockstore.MockStore{
					Store:  make(map[string][]byte),
					ErrPut: errors.New("test"),
				},
			},
		}

		o, err := operation.New(cfg)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.CreateProfile(result, newReq(t,
			http.MethodPost,
			"/profile",
			&openapi.Profile{Controller: controller()},
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to store zcap")
	})
}

func TestOperation_CreateQuery(t *testing.T) {
	t.Run("TODO - creates a query", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateQuery(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
	})
}

func TestOperation_CreateAuthorization(t *testing.T) {
	t.Run("TODO - creates an authorization", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.CreateAuthorization(result, nil)
		require.Equal(t, http.StatusCreated, result.Code)
	})
}

func TestOperation_Compare(t *testing.T) {
	t.Run("equal documents", func(t *testing.T) {
		doc := randomDoc(t)
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, doc)
		jwe2 := encryptedJWE(t, agent, doc)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, jwe1, jwe2)
		}

		payload := marshal(t, map[string]interface{}{
			"op": newEqOp(t,
				docQuery(&openapi.UpstreamAuthorization{
					BaseURL: "https://edv.example.com",
				}, nil),
				docQuery(&openapi.UpstreamAuthorization{
					BaseURL: "https://edv.example.com",
				}, nil),
			),
		})

		request := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		o.Compare(result, request)
		require.Equal(t, http.StatusOK, result.Code)
		requireCompareResult(t, true, result.Body)
	})

	t.Run("error BadRequest if cannot parse request", func(t *testing.T) {
		o := newOperation(t, agentConfig(newAgent(t)))
		result := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("'}")))

		o.Compare(result, request)
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "bad request")
	})
}

func TestOperation_Extract(t *testing.T) {
	t.Run("TODO - performs an extraction", func(t *testing.T) {
		o := newOp(t)
		result := httptest.NewRecorder()
		o.Extract(result, nil)
		require.Equal(t, http.StatusOK, result.Code)
	})
}

func newOp(t *testing.T) *operation.Operation {
	t.Helper()

	op, err := operation.New(config(t))
	require.NoError(t, err)

	return op
}

func config(t *testing.T) *operation.Config {
	t.Helper()

	return &operation.Config{
		StoreProvider: mockstore.NewMockStoreProvider(),
		Aries: &operation.AriesConfig{
			KMS:    &mockkms.KeyManager{},
			Crypto: &mockcrypto.Crypto{},
		},
	}
}

// nolint:unparam // http method should be generalized
func newReq(t *testing.T, method, path string, payload interface{}) *http.Request {
	t.Helper()

	var body io.Reader

	if payload != nil {
		raw, err := json.Marshal(payload)
		require.NoError(t, err)

		body = bytes.NewReader(raw)
	}

	return httptest.NewRequest(method, path, body)
}

func controller() *string {
	c := fmt.Sprintf("did:example:%s#key1", uuid.New().String())

	return &c
}

func randomDoc(t *testing.T) []byte {
	t.Helper()

	docID, err := edvutils.GenerateEDVCompatibleID()
	require.NoError(t, err)

	raw, err := json.Marshal(&models.StructuredDocument{
		ID: docID,
		Content: map[string]interface{}{
			"content": uuid.New().String(),
		},
	})
	require.NoError(t, err)

	return raw
}
