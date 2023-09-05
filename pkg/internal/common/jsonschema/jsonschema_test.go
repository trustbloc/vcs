/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonschema

import (
	_ "embed"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed testdata/sample_university_degree.jsonld
	sampleUniversityDegree []byte
	//go:embed testdata/sample_invalid_university_degree.jsonld
	sampleInvalidUniversityDegree []byte
	//go:embed testdata/universitydegree.schema.json
	universityDegreeSchema []byte
	//go:embed testdata/invalid.schema.json
	invalidSchema []byte
)

func TestCachingValidator_Validate(t *testing.T) {
	var schema Document
	require.NoError(t, json.Unmarshal(universityDegreeSchema, &schema))

	var validDoc map[string]interface{}
	require.NoError(t, json.Unmarshal(sampleUniversityDegree, &validDoc))

	t.Run("success", func(t *testing.T) {
		cv := NewCachingValidator()
		require.NotNil(t, cv)

		require.NoError(t, cv.Validate(validDoc, schema))

		// Should retrieve cached validator
		require.NoError(t, cv.Validate(validDoc, schema))
	})

	t.Run("validation error", func(t *testing.T) {
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal(sampleInvalidUniversityDegree, &data))

		cv := NewCachingValidator()
		require.NotNil(t, cv)

		require.EqualError(t, cv.Validate(data, schema), "validation error: [alumniOf: name is required]")
	})

	t.Run("invalid schema: no $id field", func(t *testing.T) {
		schemaDoc := Document{}

		cv := NewCachingValidator()
		require.NotNil(t, cv)

		require.EqualError(t, cv.Validate(validDoc, schemaDoc),
			"get schema validator from cache: field '$id' not found in JSON schema")
	})

	t.Run("invalid schema: $id field not a string", func(t *testing.T) {
		schemaDoc := Document{"$id": 1}

		cv := NewCachingValidator()
		require.NotNil(t, cv)

		require.EqualError(t, cv.Validate(validDoc, schemaDoc),
			"get schema validator from cache: expecting field '$id' in JSON schema to be a string type but was int")
	})

	t.Run("create validator error", func(t *testing.T) {
		cv := NewCachingValidator()
		require.NotNil(t, cv)

		cv.createValidator = func(schema Document) (Validator, error) {
			return nil, errors.New("injected create error")
		}

		err := cv.Validate(validDoc, schema)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"create validator [https://trustbloc.com/universitydegree.schema.json]: injected create error")
	})
}

func TestNewGoJSONSchemaValidator(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var schema Document
		require.NoError(t, json.Unmarshal(universityDegreeSchema, &schema))

		v, err := newValidator(schema)
		require.NoError(t, err)
		require.NotNil(t, v)
	})

	t.Run("success", func(t *testing.T) {
		var schema Document
		require.NoError(t, json.Unmarshal(invalidSchema, &schema))

		v, err := newValidator(schema)
		require.Error(t, err)
		require.Contains(t, err.Error(), "compile JSON schema: has a primitive type that is NOT VALID")
		require.Nil(t, v)
	})
}
