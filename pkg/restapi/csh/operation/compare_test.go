/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	edv "github.com/trustbloc/edv/pkg/client"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
)

func TestOperation_HandleEqOp(t *testing.T) {
	t.Run("equal documents", func(t *testing.T) {
		doc := []byte(uuid.New().String())
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, doc)
		jwe2 := encryptedJWE(t, agent, doc)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return newMockEDVClient(t, nil, jwe1, jwe2)
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		op := newEqOp(t, newDocQuery(), newDocQuery())

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusOK, result.Code)
		requireCompareResult(t, true, result.Body)
	})

	t.Run("unequal documents", func(t *testing.T) {
		agent := newAgent(t)

		jwe1 := encryptedJWE(t, agent, []byte(uuid.New().String()))
		jwe2 := encryptedJWE(t, agent, []byte(uuid.New().String()))

		edvClient := newMockEDVClient(t, nil, jwe1, jwe2)

		config := agentConfig(agent)
		config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
			return edvClient
		}

		o := newOperation(t, config)
		result := httptest.NewRecorder()

		op := newEqOp(t, newDocQuery(), newDocQuery())

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
		op := newEqOp(t, newDocQuery(), newDocQuery())

		o.HandleEqOp(result, op)
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to read Confidential Storage document")
	})

	t.Run("TODO - RefQuery not yet implemented", func(t *testing.T) {
		o := newOperation(t, agentConfig(newAgent(t)))
		result := httptest.NewRecorder()

		o.HandleEqOp(result, newEqOp(t, newRefQuery(), newDocQuery()))
		require.Equal(t, http.StatusNotImplemented, result.Code)
		require.Contains(t, result.Body.String(), "not yet implemented")
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
