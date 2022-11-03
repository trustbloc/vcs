/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

//nolint:maintidx
func TestStandardFields(t *testing.T) {
	const module = "test_module"

	t.Run("console error", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := New(module, WithStdErr(stdErr))

		logger.Error("Sample error", WithError(errors.New("some error")))

		require.Contains(t, stdErr.Buffer.String(), `Sample error	{"error": "some error"}`)
	})

	t.Run("json error", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := New(module,
			WithStdErr(stdErr), WithEncoding(JSON),
		)

		logger.Error("Sample error", WithError(errors.New("some error")))

		l := unmarshalLogData(t, stdErr.Bytes())

		require.Equal(t, "test_module", l.Logger)
		require.Equal(t, "Sample error", l.Msg)
		require.Contains(t, l.Caller, "log/fields_test.go")
		require.Equal(t, "some error", l.Error)
		require.Equal(t, "error", l.Level)
	})

	t.Run("json fields 1", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithEncoding(JSON))

		id := "123"
		name := "Joe"
		command := "some command"
		topic := "some topic"
		msg := "Some message"
		hostURL := "https://localhost:8080"
		responseBody := []byte("response body")
		token := "someToken"
		totalRequests := 10
		responses := 9
		concurrencyReq := 3
		workers := 4
		path := "some/path"
		url := "some/url"
		json := "{\"some\":\"json object\"}"
		jsonResolution := "json/resolution"
		sleep := time.Second * 10
		duration := time.Second * 20
		event := &mockObject{
			Field1: "event1",
			Field2: 123,
		}
		idToken := "some id token"
		vpToken := "some vp token"
		txID := "some tx id"
		presDefID := "some pd id"
		state := "some state"
		profileID := "some profile id"

		dockerComposeCmd := strings.Join([]string{
			"docker-compose",
			"-f",
			"/path/to/composeFile.yaml",
			"up",
			"--force-recreate",
			"-d",
		}, " ")
		certPoolSize := 3

		logger.Info("Some message",
			WithHTTPStatus(http.StatusNotFound),
			WithUserLogLevel(DEBUG.String()),
			WithID(id),
			WithName(name),
			WithCommand(command),
			WithTopic(topic),
			WithAdditionalMessage(msg),
			WithHostURL(hostURL),
			WithResponseBody(responseBody),
			WithToken(token),
			WithTotalRequests(totalRequests),
			WithResponses(responses),
			WithConcurrencyRequests(concurrencyReq),
			WithWorkers(workers),
			WithPath(path),
			WithURL(url),
			WithJSON(json),
			WithJSONResolution(jsonResolution),
			WithSleep(sleep),
			WithDuration(duration),
			WithEvent(event),
			WithDockerComposeCmd(dockerComposeCmd),
			WithCertPoolSize(certPoolSize),
			WithIDToken(idToken),
			WithVPToken(vpToken),
			WithTxID(txID),
			WithPresDefID(presDefID),
			WithState(state),
			WithProfileID(profileID),
		)

		t.Logf(stdOut.String())
		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, 404, l.HTTPStatus)
		require.Equal(t, `DEBUG`, l.UserLogLevel)
		require.Equal(t, id, l.ID)
		require.Equal(t, name, l.Name)
		require.Equal(t, command, l.Command)
		require.Equal(t, topic, l.Topic)
		require.Equal(t, msg, l.Msg)
		require.Equal(t, hostURL, l.HostURL)
		require.EqualValues(t, responseBody, l.ResponseBody)
		require.Equal(t, token, l.Token)
		require.Equal(t, totalRequests, l.TotalRequests)
		require.Equal(t, responses, l.Responses)
		require.Equal(t, concurrencyReq, l.ConcurrencyRequests)
		require.Equal(t, workers, l.Workers)
		require.Equal(t, path, l.Path)
		require.Equal(t, url, l.URL)
		require.Equal(t, json, l.JSON)
		require.Equal(t, jsonResolution, l.JSONResolution)
		require.Equal(t, sleep.String(), l.Sleep)
		require.Equal(t, event, l.Event)
		require.Equal(t, dockerComposeCmd, l.DockerComposeCmd)
		require.Equal(t, certPoolSize, l.CertPoolSize)
		require.Equal(t, idToken, l.IDToken)
		require.Equal(t, vpToken, l.VPToken)
		require.Equal(t, txID, l.TxID)
		require.Equal(t, presDefID, l.PresDefID)
		require.Equal(t, state, l.State)
		require.Equal(t, profileID, l.ProfileID)
	})

	t.Run("json fields 2", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithEncoding(JSON))

		logger.Info("Some message")

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
	})
}

type mockObject struct {
	Field1 string
	Field2 int
}

type logData struct {
	Level  string `json:"level"`
	Time   string `json:"time"`
	Logger string `json:"logger"`
	Caller string `json:"caller"`
	Msg    string `json:"msg"`
	Error  string `json:"error"`

	HTTPStatus          int         `json:"httpStatus"`
	UserLogLevel        string      `json:"userLogLevel"`
	ID                  string      `json:"id"`
	Name                string      `json:"name"`
	Command             string      `json:"command"`
	Topic               string      `json:"topic"`
	AdditionalMessage   string      `json:"additionalMessage"`
	HostURL             string      `json:"hostURL"`
	ResponseBody        string      `json:"responseBody"`
	Token               string      `json:"token"`
	TotalRequests       int         `json:"totalRequests"`
	Responses           int         `json:"responses"`
	ConcurrencyRequests int         `json:"concurrencyRequests"`
	Workers             int         `json:"workers"`
	Path                string      `json:"path"`
	URL                 string      `json:"url"`
	JSON                string      `json:"json"`
	JSONResolution      string      `json:"jsonResolution"`
	Sleep               string      `json:"sleep"`
	Duration            string      `json:"duration"`
	Event               *mockObject `json:"event"`
	DockerComposeCmd    string      `json:"dockerComposeCmd"`
	CertPoolSize        int         `json:"certPoolSize"`
	IDToken             string      `json:"idToken"`
	VPToken             string      `json:"vpToken"`
	TxID                string      `json:"transactionID"`
	PresDefID           string      `json:"presDefinitionID"`
	State               string      `json:"state"`
	ProfileID           string      `json:"profileID"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}
