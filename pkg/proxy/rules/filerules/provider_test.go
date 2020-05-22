/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filerules

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider, err := New("./test/config.json")
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("error", func(t *testing.T) {
		provider, err := New("./test/non-existent.json")
		require.Error(t, err)
		require.Nil(t, provider)
		require.Contains(t, err.Error(), "failed to read config file")
	})
	t.Run("error", func(t *testing.T) {
		provider, err := New("./test/invalid.json")
		require.Error(t, err)
		require.Nil(t, provider)
		require.Contains(t, err.Error(), "failed to unmarshal proxy config file")
	})
}

func TestParseConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rules, err := getPatternRules([]byte(validConfig))
		require.NoError(t, err)
		require.NotNil(t, rules)
	})
	t.Run("error - invalid JSON", func(t *testing.T) {
		rules, err := getPatternRules([]byte(invalidJSON))
		require.Error(t, err)
		require.Nil(t, rules)
		require.Contains(t, err.Error(), "failed to unmarshal proxy config file")
	})
	t.Run("error - invalid pattern", func(t *testing.T) {
		rules, err := getPatternRules([]byte(invalidPattern))
		require.Error(t, err)
		require.Nil(t, rules)
		require.Contains(t, err.Error(), "failed to compile rule pattern")
	})
	t.Run("success - valid file, no rules, log warning", func(t *testing.T) {
		rules, err := getPatternRules([]byte(`{"rules":[]}`))
		require.NoError(t, err)
		require.Empty(t, rules)
	})
}

func TestProvider_Transform(t *testing.T) {
	provider, err := New("./test/config.json")
	require.NoError(t, err)
	require.NotNil(t, provider)

	t.Run("success - trustbloc pattern", func(t *testing.T) {
		uri, err := provider.Transform("did:trustbloc:testnet.trustbloc.local:abc")
		require.NoError(t, err)
		require.NotEmpty(t, uri)
	})
	t.Run("success - default did pattern", func(t *testing.T) {
		uri, err := provider.Transform("did:method:abc")
		require.NoError(t, err)
		require.NotEmpty(t, uri)
	})
	t.Run("success - did key pattern, no url", func(t *testing.T) {
		uri, err := provider.Transform("did:key:abc")
		require.NoError(t, err)
		require.Empty(t, uri)
	})
	t.Run("error - no did pattern", func(t *testing.T) {
		uri, err := provider.Transform("doc:abc:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "no match")
		require.Empty(t, uri)
	})
}

const validConfig = `
{
  "rules": [
    {
      "pattern": "^(did:trustbloc:testnet.trustbloc.local:.+)$",
      "url": "http://trustbloc.did.method.example.com:8060/resolveDID?did=$1"
    },
    {
      "pattern": "^(did:key:.+)$"
    },
    {
      "pattern": "^(did:.+)$",
      "url": "http://uniresolver.example.com:8070/1.0/identifiers/$1"
    }
  ]
}
`

const invalidJSON = `
  "rules": [
    {
      "pattern": "^(did:trustbloc:testnet.trustbloc.local:.+)$",
      "url": "http://trustbloc.did.method.example.com:8060/resolveDID?did=$1"
    }
`

const invalidPattern = `{
  "rules": [
    {
      "pattern": "BOOM\\",
      "url": "http://example.com/$1"
    }
  ]
}
`
