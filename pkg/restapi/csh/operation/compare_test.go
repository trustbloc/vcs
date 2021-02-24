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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	edv "github.com/trustbloc/edv/pkg/client"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
)

func TestOperation_HandleEqOp(t *testing.T) {
	t.Run("equal documents - 2 doc queries", func(t *testing.T) {
		doc := randomDoc(t)
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, doc)
		jwe2 := encryptedJWE(t, agent, doc)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, jwe1, jwe2)
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		op := newEqOp(t,
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
		)

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusOK, result.Code)
		requireCompareResult(t, true, result.Body)
	})

	t.Run("equal documents - 1 DocQuery, 1 RefQuery", func(t *testing.T) {
		doc := randomDoc(t)
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, doc)
		jwe2 := encryptedJWE(t, agent, doc)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, jwe1, jwe2)
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		o.CreateQuery(
			result,
			httptest.NewRequest(
				http.MethodPost,
				"/test",
				bytes.NewReader(marshal(t, docQuery(
					&openapi.UpstreamAuthorization{
						BaseURL: "https://edv.example.com/encrypted-data-vaults",
						Zcap:    compress(t, marshal(t, newZCAP(t, agent, agent))),
					},
					nil,
				))),
			),
		)
		require.Equal(t, http.StatusCreated, result.Code)
		location := result.Header().Get("location")
		require.NotEmpty(t, location)
		parts := strings.Split(location, "/")
		queryID := parts[len(parts)-1]

		op := newEqOp(t,
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
			refQuery(queryID),
		)

		result = httptest.NewRecorder()

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusOK, result.Code)
		requireCompareResult(t, true, result.Body)
	})

	t.Run("unequal documents", func(t *testing.T) {
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, randomDoc(t))
		jwe2 := encryptedJWE(t, agent, randomDoc(t))

		edvClient := newMockEDVClient(t, nil, jwe1, jwe2)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return edvClient
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		op := newEqOp(t,
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
		)

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusOK, result.Code)
		requireCompareResult(t, false, result.Body)
	})

	t.Run("error BadRequest if there are less than 2 args", func(t *testing.T) {
		o := newOperation(t, agentConfig(newAgent(t)))
		result := httptest.NewRecorder()

		o.HandleEqOp(result, newEqOp(t))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "requires at least two arguments")
	})

	t.Run("error reading DocQuery", func(t *testing.T) {
		config := agentConfig(newAgent(t))
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, errors.New("test"))
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()
		op := newEqOp(t, newDocQuery(t), newDocQuery(t))

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to read Confidential Storage document")
	})

	t.Run("error parsing results of doc query", func(t *testing.T) {
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, []byte("INVALID"))
		jwe2 := encryptedJWE(t, agent, randomDoc(t))

		edvClient := newMockEDVClient(t, nil, jwe1, jwe2)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return edvClient
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		op := newEqOp(t,
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
		)

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to parse Confidential Storage structured document")
	})

	t.Run("error BadRequest if query ref does not exist", func(t *testing.T) {
		o := newOperation(t, config(t))
		result := httptest.NewRecorder()

		o.HandleEqOp(result, newEqOp(t,
			refQuery("INVALID"),
			refQuery("INVALID"),
		))

		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "no such query")
	})

	t.Run("error InternalServerError if cannot fetch query object from store", func(t *testing.T) {
		expected := errors.New("test error")
		config := config(t)
		config.StoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					"test": []byte("value"),
				},
				ErrGet: expected,
			},
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		o.HandleEqOp(result, newEqOp(t,
			refQuery("test"),
			refQuery("test"),
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to fetch query object for ref")
	})

	t.Run("error InternalServerError if cannot fetch EDV document with RefQuery", func(t *testing.T) {
		queryID := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					queryID: marshal(t, &operation.Query{
						ID:        queryID,
						ProfileID: uuid.New().String(),
						Spec: marshal(t, docQuery(
							&openapi.UpstreamAuthorization{
								BaseURL: "https://edv.example.com/encrypted-data-vaults",
								Zcap:    compress(t, marshal(t, newZCAP(t, newAgent(t), newAgent(t)))),
							},
							nil,
						)),
					}),
				},
			},
		}
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, errors.New("test"))
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		o.HandleEqOp(result, newEqOp(t,
			refQuery(queryID),
			refQuery(queryID),
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to read Confidential Storage document")
	})

	t.Run("error InternalServerError if cannot parse EDV document with RefQuery", func(t *testing.T) {
		queryID := uuid.New().String()
		agent := newAgent(t)
		config := agentConfig(agent)
		config.StoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					queryID: marshal(t, &operation.Query{
						ID:        queryID,
						ProfileID: uuid.New().String(),
						Spec: marshal(t, docQuery(
							&openapi.UpstreamAuthorization{
								BaseURL: "https://edv.example.com/encrypted-data-vaults",
								Zcap:    compress(t, marshal(t, newZCAP(t, agent, agent))),
							},
							nil,
						)),
					}),
				},
			},
		}
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, encryptedJWE(t, agent, []byte("'}")))
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		o.HandleEqOp(result, newEqOp(t,
			refQuery(queryID),
			refQuery(queryID),
		))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to parse Confidential Storage structured document")
	})

	t.Run("error on malformed jsonpath", func(t *testing.T) {
		doc := randomDoc(t)
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, doc)
		jwe2 := encryptedJWE(t, agent, doc)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, jwe1, jwe2)
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		query1 := docQuery(&openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
		}, nil)

		query1.Path = "}"

		op := newEqOp(t,
			query1,
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
		)

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to build new json path evaluator")
	})

	t.Run("error on invalid jsonpath", func(t *testing.T) {
		doc := randomDoc(t)
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, doc)
		jwe2 := encryptedJWE(t, agent, doc)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, jwe1, jwe2)
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		query1 := docQuery(&openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
		}, nil)

		query1.Path = "$.invalid.path"

		op := newEqOp(t,
			query1,
			docQuery(&openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			}, nil),
		)

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to evaluate json path")
	})
}

func requireCompareResult(t *testing.T, expected bool, r io.Reader) {
	t.Helper()

	actual := &openapi.Comparison{}

	err := json.NewDecoder(r).Decode(actual)
	require.NoError(t, err)

	require.Equal(t, expected, actual.Result)
}

func newEqOp(t *testing.T, queries ...interface{}) *openapi.EqOp {
	t.Helper()

	payload := map[string]interface{}{
		"type": "EqOp",
		"args": queries,
	}

	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	op := &openapi.EqOp{}

	err = json.Unmarshal(raw, op)
	require.NoError(t, err)

	return op
}
