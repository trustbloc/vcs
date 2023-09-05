/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/require"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

func Test_populateCredentialTemplates(t *testing.T) {
	t.Run("success with schema", func(t *testing.T) {
		ct := &profileapi.CredentialTemplate{
			JSONSchema: jsonSchema,
		}

		err := populateJSONSchemaID(ct)
		require.NoError(t, err)
		require.NotEmpty(t, ct.JSONSchemaID)

		require.Equal(t, "https://trustbloc.com/universitydegree.schema.json", ct.JSONSchemaID)
	})

	t.Run("success no schema", func(t *testing.T) {
		ct := &profileapi.CredentialTemplate{}

		err := populateJSONSchemaID(ct)
		require.NoError(t, err)
		require.Empty(t, ct.JSONSchemaID)
	})

	t.Run("unmarshal error in schema", func(t *testing.T) {
		ct := &profileapi.CredentialTemplate{
			JSONSchema: `{`,
		}

		err := populateJSONSchemaID(ct)
		require.EqualError(t, err, "unmarshal JSON schema: unexpected end of JSON input")
	})

	t.Run("missing `$id` field", func(t *testing.T) {
		ct := &profileapi.CredentialTemplate{
			JSONSchema: `{}`,
		}

		err := populateJSONSchemaID(ct)
		require.EqualError(t, err, "missing $id field in JSON schema")
	})

	t.Run("invalid `$id` field", func(t *testing.T) {
		ct := &profileapi.CredentialTemplate{
			JSONSchema: `{"$id":1}`,
		}

		err := populateJSONSchemaID(ct)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting field '$id' in JSON schema to be a string type")
	})
}

const jsonSchema = `{
  "$id": "https://trustbloc.com/universitydegree.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "UniversityDegreeCredential",
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    }
  }
}`
