/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edge-service/pkg/restapi/model"
)

const testLogSpec = `{"spec":"edge-service-issuer-restapi=debug:vc-rest=critical:error"}`

type mockStringBuilder struct {
	numWrites          int
	numWritesBeforeErr int
}

func (m *mockStringBuilder) Write(p []byte) (int, error) {
	if m.numWrites == m.numWritesBeforeErr {
		return 0, errors.New("mockStringBuilder write failure")
	}

	m.numWrites++

	return 0, nil
}

func (m *mockStringBuilder) String() string {
	panic("implement me")
}

func (m *mockStringBuilder) Reset() {}

func TestLogSpecPut(t *testing.T) {
	t.Run("Successfully set logging levels", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(testLogSpec)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)

		require.Equal(t, log.DEBUG, log.GetLevel("edge-service-issuer-restapi"))
		require.Equal(t, log.CRITICAL, log.GetLevel("vc-rest"))
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Empty request body", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer(nil))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response model.ErrorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, "EOF"), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: default log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":"InvalidLogLevel"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response model.ErrorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, "logger: invalid log level"), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: module log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "",
			bytes.NewBuffer([]byte(`{"spec":"Module1=InvalidLogLevel"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		var response model.ErrorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, "logger: invalid log level"), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: multiple default log levels", func(t *testing.T) {
		resetLoggingLevels()

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":"debug:debug"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		changeLogSpec(rr, req)

		var response model.ErrorResponse

		err = json.Unmarshal(rr.Body.Bytes(), &response)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf(invalidLogSpec, multipleDefaultValues), response.Message)

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestLogSpecGet(t *testing.T) {
	t.Run("Successfully get logging levels", func(t *testing.T) {
		resetLoggingLevels()

		rr := httptest.NewRecorder()

		logSpecGetHandler(rr, nil)

		require.Equal(t, http.StatusOK, rr.Code)

		var logSpecResponse logSpec
		err := json.Unmarshal(rr.Body.Bytes(), &logSpecResponse)
		require.NoError(t, err)

		// The two expected strings below are equivalent. Depending on the order of the entries
		//  in the underlying log levels map, either is a possible (and valid) result.
		gotExpectedLevels := logSpecResponse.Spec == "edge-service-issuer-restapi=INFO:vc-rest=INFO:INFO" ||
			logSpecResponse.Spec == "vc-rest=INFO:edge-service-issuer-restapi=INFO:INFO"
		require.True(t, gotExpectedLevels)
	})
	t.Run("Fail to write module name and level to stringBuilder", func(t *testing.T) {
		resetLoggingLevels()

		rr := httptest.NewRecorder()

		getLogSpec(rr, &mockStringBuilder{})

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("Fail to write default log level to stringBuilder", func(t *testing.T) {
		resetLoggingLevels()

		rr := httptest.NewRecorder()

		getLogSpec(rr, &mockStringBuilder{numWritesBeforeErr: 2})

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func resetLoggingLevels() {
	log.SetLevel("edge-service-issuer-restapi", log.INFO)
	log.SetLevel("vc-rest", log.INFO)
	log.SetLevel("", log.INFO)
}
