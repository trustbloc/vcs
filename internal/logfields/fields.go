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
	FieldAdditionalMessage    = "additionalMessage"
	FieldCommand              = "command"
	FieldConcurrencyRequests  = "concurrencyRequests"
	FieldDockerComposeCmd     = "dockerComposeCmd"
	FieldEvent                = "event"
	FieldIDToken              = "idToken"
	FieldTransactionID        = "transactionId"
	FieldJSONQuery            = "JSONQuery"
	FieldJSONResolution       = "JSONResolution"
	FieldPresDefID            = "presDefID"
	FieldProfileID            = "profileID"
	FieldProfileVersion       = "profileVersion"
	FieldCredentialID         = "credentialID" //nolint:gosec
	FieldResponses            = "responses"
	FieldSleep                = "sleep"
	FieldTotalRequests        = "totalRequests"
	FieldUserLogLevel         = "userLogLevel"
	FieldVP                   = "vp"
	FieldVPToken              = "vpToken"
	FieldWorkers              = "workers"
	FieldClaimKeys            = "claimKeys"
	FieldCredentialTemplateID = "credentialTemplateID" //nolint:gosec
	FieldJSONSchemaID         = "jsonSchemaID"
	FieldJSONSchema           = "jsonSchema"
	FieldContext              = "context"
	FieldIssuerID             = "issuerID"
	FieldStatusListIssuerID   = "statusListIssuerID"
	FieldStatusPurpose        = "statusPurpose"
	FieldStatusType           = "statusType"
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

// WithTransactionID sets the id token field.
func WithTransactionID(transactionID string) zap.Field {
	return zap.String(FieldTransactionID, transactionID)
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

// WithProfileVersion sets the ProfileVersion field.
func WithProfileVersion(profileVersion string) zap.Field {
	return zap.String(FieldProfileVersion, profileVersion)
}

// WithCredentialID sets the CredentialID field.
func WithCredentialID(credentialID string) zap.Field {
	return zap.String(FieldCredentialID, credentialID)
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

// WithCredentialTemplateID sets the credentialTemplateID field.
func WithCredentialTemplateID(value string) zap.Field {
	return zap.String(FieldCredentialTemplateID, value)
}

// WithJSONSchemaID sets the jsonSchemaID field.
func WithJSONSchemaID(value string) zap.Field {
	return zap.String(FieldJSONSchemaID, value)
}

// WithJSONSchema sets the jsonSchema field.
func WithJSONSchema(value string) zap.Field {
	return zap.String(FieldJSONSchema, value)
}

// WithContext sets the context field.
func WithContext(ctx []string) zap.Field {
	return zap.Strings(FieldContext, ctx)
}

// WithIssuerID sets the issuerID field.
func WithIssuerID(value string) zap.Field {
	return zap.String(FieldIssuerID, value)
}

// WithStatusListIssuerID sets the statusListIssuerID field.
func WithStatusListIssuerID(value string) zap.Field {
	return zap.String(FieldStatusListIssuerID, value)
}

// WithStatusPurpose sets the statusPurpose field.
func WithStatusPurpose(statusPurpose string) zap.Field {
	return zap.String(FieldStatusPurpose, statusPurpose)
}

// WithStatusType sets the statusType field.
func WithStatusType(statusType string) zap.Field {
	return zap.String(FieldStatusType, statusType)
}
