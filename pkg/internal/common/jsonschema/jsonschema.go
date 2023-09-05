/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonschema

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/xeipuuv/gojsonschema"

	"github.com/trustbloc/logutil-go/pkg/log"
)

var logger = log.New("jsonschema")

// Document holds the JSON schema document.
type Document map[string]interface{}

// Validator is a JSON schema validator.
type Validator interface {
	ValidateJSONSchema(data interface{}) error
}

type validatorFactory func(schema Document) (Validator, error)

// CachingValidator implements a caching JSON schema validator where a give schema is compiled once
// for the validator and is reused for subsequent validations.
type CachingValidator struct {
	cache           map[string]Validator
	createValidator validatorFactory
	mutex           sync.RWMutex
}

// NewCachingValidator returns a new caching JSON schema validator.
func NewCachingValidator() *CachingValidator {
	return &CachingValidator{
		cache:           make(map[string]Validator),
		createValidator: newValidator,
	}
}

// Validate validates the given JSON document against the given schema.
func (c *CachingValidator) Validate(data interface{}, schema Document) error {
	validator, err := c.get(schema)
	if err != nil {
		return fmt.Errorf("get schema validator from cache: %w", err)
	}

	return validator.ValidateJSONSchema(data)
}

func (c *CachingValidator) get(schema Document) (Validator, error) {
	schemaIDObj, ok := schema["$id"]
	if !ok {
		return nil, fmt.Errorf("field '$id' not found in JSON schema")
	}

	schemaID, ok := schemaIDObj.(string)
	if !ok {
		return nil, fmt.Errorf("expecting field '$id' in JSON schema to be a string type but was %s",
			reflect.TypeOf(schemaIDObj))
	}

	c.mutex.RLock()
	v, ok := c.cache[schemaID]
	c.mutex.RUnlock()

	if ok {
		return v, nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	schemaValidator, err := c.createValidator(schema)
	if err != nil {
		return nil, fmt.Errorf("create validator [%s]: %w", schemaID, err)
	}

	c.cache[schemaID] = schemaValidator

	logger.Debug("Created validator for JSON schema", log.WithID(schemaID))

	return schemaValidator, nil
}

func newValidator(schema Document) (Validator, error) {
	schemaValidator, err := gojsonschema.NewSchemaLoader().Compile(gojsonschema.NewGoLoader(schema))
	if err != nil {
		return nil, fmt.Errorf("compile JSON schema: %w", err)
	}

	return &validator{schema: schemaValidator}, nil
}

type validator struct {
	schema *gojsonschema.Schema
}

func (v *validator) ValidateJSONSchema(data interface{}) error {
	result, err := v.schema.Validate(gojsonschema.NewGoLoader(data))
	if err != nil {
		return fmt.Errorf("loader error: %w", err)
	}

	if !result.Valid() {
		return fmt.Errorf("validation error: %w", validationErrors(result.Errors()))
	}

	return nil
}

type validationErrors []gojsonschema.ResultError

func (e validationErrors) Error() string {
	var errMsg string

	for i, msg := range e {
		errMsg += msg.String()
		if i+1 < len(e) {
			errMsg += "; "
		}
	}

	return fmt.Sprintf("[%s]", errMsg)
}
