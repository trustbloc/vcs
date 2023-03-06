/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logfields

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log Fields.
const (
	FieldAdditionalMessage   = "additionalMessage"
	FieldCommand             = "command"
	FieldConcurrencyRequests = "concurrencyRequests"
	FieldDockerComposeCmd    = "dockerComposeCmd"
	FieldEvent               = "event"
	FieldIDToken             = "idToken"
	FieldJSONQuery           = "JSONQuery"
	FieldJSONResolution      = "JSONResolution"
	FieldPresDefID           = "presDefID"
	FieldProfileID           = "profileID"
	FieldResponses           = "responses"
	FieldSleep               = "sleep"
	FieldTotalRequests       = "totalRequests"
	FieldUserLogLevel        = "userLogLevel"
	FieldVP                  = "vp"
	FieldVPToken             = "vpToken"
	FieldWorkers             = "workers"
	FieldClaimKeys           = "claimKeys"
)

// WithAdditionalMessage sets the AdditionalMessage field.
func WithAdditionalMessage(value string) zap.Field {
	return zap.Any(FieldAdditionalMessage, value)
}

// WithCommand sets the Command field.
func WithCommand(command string) zap.Field {
	return zap.String(FieldCommand, command)
}

// WithConcurrencyRequests sets the ConcurrencyRequests field.
func WithConcurrencyRequests(concurrencyRequests int) zap.Field {
	return zap.Int(FieldConcurrencyRequests, concurrencyRequests)
}

// WithDockerComposeCmd sets the DockerComposeCmd field.
func WithDockerComposeCmd(dockerComposeCmd string) zap.Field {
	return zap.String(FieldDockerComposeCmd, dockerComposeCmd)
}

// WithEvent sets the Event field.
func WithEvent(event interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldEvent, event))
}

// WithIDToken sets the id token field.
func WithIDToken(idToken string) zap.Field {
	return zap.String(FieldIDToken, idToken)
}

// WithJSONQuery sets the JSON Query field.
func WithJSONQuery(jsonQuery string) zap.Field {
	return zap.String(FieldJSONQuery, jsonQuery)
}

// WithJSONResolution sets the JSONResolution field.
func WithJSONResolution(jsonResolution string) zap.Field {
	return zap.String(FieldJSONResolution, jsonResolution)
}

// WithPresDefID sets the PresDefID (presentation definition ID) field.
func WithPresDefID(presDefID string) zap.Field {
	return zap.String(FieldPresDefID, presDefID)
}

// WithProfileID sets the ProfileID field.
func WithProfileID(profileID string) zap.Field {
	return zap.String(FieldProfileID, profileID)
}

// WithResponses sets the Responses field.
func WithResponses(responses int) zap.Field {
	return zap.Int(FieldResponses, responses)
}

// WithSleep sets the sleep field.
func WithSleep(sleep time.Duration) zap.Field {
	return zap.Duration(FieldSleep, sleep)
}

// WithTotalRequests sets the TotalRequests field.
func WithTotalRequests(totalRequests int) zap.Field {
	return zap.Int(FieldTotalRequests, totalRequests)
}

// WithUserLogLevel sets the UserLogLevel field.
func WithUserLogLevel(logLevel string) zap.Field {
	return zap.String(FieldUserLogLevel, logLevel)
}

// WithVP sets the VP (verifiable presentation) field.
func WithVP(vp string) zap.Field {
	return zap.String(FieldVP, vp)
}

// WithVPToken sets the vp token field.
func WithVPToken(vpToken string) zap.Field {
	return zap.String(FieldVPToken, vpToken)
}

// WithWorkers sets the Workers field.
func WithWorkers(workers int) zap.Field {
	return zap.Int(FieldWorkers, workers)
}

// WithClaimKeys sets the Claim fields.
func WithClaimKeys(claimKeys []string) zap.Field {
	return zap.Strings(FieldClaimKeys, claimKeys)
}

// ObjectMarshaller uses reflection to marshal an object's fields.
type ObjectMarshaller struct {
	key string
	obj interface{}
}

// NewObjectMarshaller returns a new ObjectMarshaller.
func NewObjectMarshaller(key string, obj interface{}) *ObjectMarshaller {
	return &ObjectMarshaller{key: key, obj: obj}
}

// MarshalLogObject marshals the object's fields.
func (m *ObjectMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	return e.AddReflected(m.key, m.obj)
}
