/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestObjectStore_Publish(t *testing.T) {
	data := map[string]string{
		"a": "b",
	}

	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)

	host := "https://example.com"
	tmp := os.TempDir()

	store := NewRequestObjectStore(host, tmp)

	fileURL, err := store.Publish(string(dataBytes))
	require.NoError(t, err)

	fileName := strings.TrimPrefix(fileURL, host+"/")

	createdFilePath := filepath.Join(tmp, fileName)
	createdFile, err := os.ReadFile(createdFilePath)
	require.NoError(t, err)

	if !reflect.DeepEqual(dataBytes, createdFile) {
		t.Errorf("Publish() got = %v, want %v", createdFile, dataBytes)
	}

	err = store.Remove(createdFilePath)
	require.NoError(t, err)
}
