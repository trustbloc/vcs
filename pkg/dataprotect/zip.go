/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dataprotect

import "strings"

func NewCompressor(algo string) DataCompressor {
	switch strings.ToLower(algo) {
	case "gzip":
		return NewGzip()
	case "zstd":
		return NewZStd()
	default:
		return NewNilZip()
	}
}
