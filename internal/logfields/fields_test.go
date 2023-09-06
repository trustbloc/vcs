/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logfields

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
)

//nolint:maintidx
func TestStandardFields(t *testing.T) {
	const (
		module = "test_module"
	)

	t.Run("json fields", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		additionalMessage := "some additional message"
		jsonQuery := "jsonQuery"
		jsonResolution := "jsonResolution"
		command := "echo 'hello world'"
		concurrencyRequests := 3
		dockerComposeCmd := "docker-compose up"
		event := &mockObject{
			Field1: "event1",
			Field2: 123,
		}
		idToken := "someIDToken"
		presDefID := "somePresDefID"
		profileID := "123"
		responses := 7
		sleep := time.Second * 10
		totalRequests := 10
		userLoglevel := "INFO"
		vp := "{}"
		vpToken := "somVPToken"
		workers := 5
		claimKeys := []string{"1", "2"}
		tranasctionID := "someTransactionID"
		credentialTemplateID := "someCredentialTemplateID"
		jsonSchemaID := "someSchemaID"
		jsonSchema := "someSchema"

		logger.Info(
			"Some message",
			WithAdditionalMessage(additionalMessage),
			WithCommand(command),
			WithConcurrencyRequests(concurrencyRequests),
			WithDockerComposeCmd(dockerComposeCmd),
			WithEvent(event),
			WithIDToken(idToken),
			WithJSONQuery(jsonQuery),
			WithTransactionID(tranasctionID),
			WithJSONResolution(jsonResolution),
			WithPresDefID(presDefID),
			WithProfileID(profileID),
			WithResponses(responses),
			WithSleep(sleep),
			WithTotalRequests(totalRequests),
			WithUserLogLevel(userLoglevel),
			WithVP(vp),
			WithVPToken(vpToken),
			WithWorkers(workers),
			WithClaimKeys(claimKeys),
			WithCredentialTemplateID(credentialTemplateID),
			WithJSONSchemaID(jsonSchemaID),
			WithJSONSchema(jsonSchema),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, additionalMessage, l.AdditionalMessage)
		require.Equal(t, command, l.Command)
		require.Equal(t, concurrencyRequests, l.ConcurrencyRequests)
		require.Equal(t, dockerComposeCmd, l.DockerComposeCmd)
		require.Equal(t, event, l.Event)
		require.Equal(t, idToken, l.IDToken)
		require.Equal(t, jsonQuery, l.JSONQuery)
		require.Equal(t, jsonResolution, l.JSONResolution)
		require.Equal(t, presDefID, l.PresDefID)
		require.Equal(t, responses, l.Responses)
		require.Equal(t, tranasctionID, l.TransactionID)
		require.Equal(t, sleep.String(), l.Sleep)
		require.Equal(t, totalRequests, l.TotalRequests)
		require.Equal(t, userLoglevel, l.UserLogLevel)
		require.Equal(t, vp, l.VP)
		require.Equal(t, vpToken, l.VPToken)
		require.Equal(t, workers, l.Workers)
		require.Equal(t, claimKeys, l.ClaimKeys)
		require.Equal(t, credentialTemplateID, l.CredentialTemplateID)
		require.Equal(t, jsonSchemaID, l.JSONSchemaID)
		require.Equal(t, jsonSchema, l.JSONSchema)
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

	AdditionalMessage    string      `json:"additionalMessage"`
	Command              string      `json:"command"`
	ConcurrencyRequests  int         `json:"concurrencyRequests"`
	DockerComposeCmd     string      `json:"dockerComposeCmd"`
	Event                *mockObject `json:"event"`
	IDToken              string      `json:"idToken"`
	JSONQuery            string      `json:"jsonQuery"`
	JSONResolution       string      `json:"jsonResolution"`
	PresDefID            string      `json:"presDefID"`
	ProfileID            string      `json:"profileID"`
	Responses            int         `json:"responses"`
	TransactionID        string      `json:"transactionID"`
	Sleep                string      `json:"sleep"`
	TotalRequests        int         `json:"totalRequests"`
	UserLogLevel         string      `json:"userLogLevel"`
	VP                   string      `json:"vp"`
	VPToken              string      `json:"vpToken"`
	Workers              int         `json:"workers"`
	ClaimKeys            []string    `json:"claimKeys"`
	CredentialTemplateID string      `json:"credentialTemplateID"`
	JSONSchemaID         string      `json:"JSONSchemaID"`
	JSONSchema           string      `json:"JSONSchema"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}

type mockWriter struct {
	*bytes.Buffer
}

func (m *mockWriter) Sync() error {
	return nil
}

func newMockWriter() *mockWriter {
	return &mockWriter{Buffer: bytes.NewBuffer(nil)}
}
