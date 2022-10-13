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
		topic := "some topic"
		msg := "Some message"
		hostURL := "https://localhost:8080"
		token := "someToken"
		totalRequests := 10
		responses := 9
		concurrencyReq := 3
		workers := 4
		path := "some/path"
		json := "{\"some\":\"json object\"}"
		jsonResolution := "json/resolution"
		sleep := time.Second * 10
		event := &mockObject{
			Field1: "event1",
			Field2: 123,
		}
		dockerComposeCmd := strings.Join([]string{
			"docker-compose",
			"-f",
			"/path/to/composeFile.yaml",
			"up",
			"--force-recreate",
			"-d",
		}, " ")

		logger.Info("Some message",
			WithHTTPStatus(http.StatusNotFound),
			WithUserLogLevel(DEBUG.String()),
			WithID(id),
			WithName(name),
			WithTopic(topic),
			WithAdditionalMessage(msg),
			WithHostURL(hostURL),
			WithToken(token),
			WithTotalRequests(totalRequests),
			WithResponses(responses),
			WithConcurrencyRequests(concurrencyReq),
			WithWorkers(workers),
			WithPath(path),
			WithJSON(json),
			WithJSONResolution(jsonResolution),
			WithSleep(sleep),
			WithEvent(event),
			WithDockerComposeCmd(dockerComposeCmd),
		)

		t.Logf(stdOut.String())
		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, 404, l.HTTPStatus)
		require.Equal(t, `DEBUG`, l.UserLogLevel)
		require.Equal(t, id, l.ID)
		require.Equal(t, name, l.Name)
		require.Equal(t, topic, l.Topic)
		require.Equal(t, msg, l.Msg)
		require.Equal(t, hostURL, l.HostURL)
		require.Equal(t, token, l.Token)
		require.Equal(t, totalRequests, l.TotalRequests)
		require.Equal(t, responses, l.Responses)
		require.Equal(t, concurrencyReq, l.ConcurrencyRequests)
		require.Equal(t, workers, l.Workers)
		require.Equal(t, path, l.Path)
		require.Equal(t, json, l.JSON)
		require.Equal(t, jsonResolution, l.JSONResolution)
		require.Equal(t, sleep.String(), l.Sleep)
		require.Equal(t, event, l.Event)
		require.Equal(t, dockerComposeCmd, l.DockerComposeCmd)
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
	Topic               string      `json:"topic"`
	AdditionalMessage   string      `json:"additionalMessage"`
	HostURL             string      `json:"hostURL"`
	Token               string      `json:"token"`
	TotalRequests       int         `json:"totalRequests"`
	Responses           int         `json:"responses"`
	ConcurrencyRequests int         `json:"concurrencyRequests"`
	Workers             int         `json:"workers"`
	Path                string      `json:"path"`
	JSON                string      `json:"json"`
	JSONResolution      string      `json:"jsonResolution"`
	Sleep               string      `json:"sleep"`
	Event               *mockObject `json:"event"`
	DockerComposeCmd    string      `json:"dockerComposeCmd"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}
