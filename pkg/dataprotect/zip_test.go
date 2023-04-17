/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/dataprotect"
)

// Rest of the tests (TestNullZipCompress, TestNullZipDecompress, TestZStdCompress, TestZStdDecompress)

func TestNewCompressor(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		wantType string
	}{
		{"NilZip", "unknown", "*dataprotect.NilZip"},
		{"Gzip", "gzip", "*dataprotect.GZip"},
		{"ZStd", "zstd", "*dataprotect.ZStd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressor := dataprotect.NewCompressor(tt.algo)
			assert.NotNil(t, compressor, "Compressor should not be nil")
			assert.Equal(t, tt.wantType, fmt.Sprintf("%T", compressor), "Compressor type should match the expected type")
		})
	}
}
