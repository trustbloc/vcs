/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

type Format string

const (
	Jwt Format = "jwt"
	Ldp Format = "ldp"
)

type FormatMetadata struct {
	Data             []byte
	Format           Format
	SDJWTDisclosures string
}

func ValidateFormat(data interface{}, formats []Format) (*FormatMetadata, error) {
	strRep, isStr := data.(string)

	if isStr {
		if !isFormatSupported(Jwt, formats) {
			return nil, fmt.Errorf("invlaid format, should be %s", Jwt)
		}

		metadata := &FormatMetadata{
			Data:   []byte(strRep),
			Format: Jwt,
		}

		index := strings.Index(strRep, common.CombinedFormatSeparator)
		if index > 0 {
			metadata.Data = []byte(strRep[:index])
			metadata.SDJWTDisclosures = strRep[index+1:]
		}

		return metadata, nil
	}

	if !isFormatSupported(Ldp, formats) {
		return nil, fmt.Errorf("invlaid format, should be %s", Ldp)
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("invlaid format: %w", err)
	}

	return &FormatMetadata{
		Data:   dataBytes,
		Format: Ldp,
	}, nil
}

func isFormatSupported(format Format, supportedFormats []Format) bool {
	for _, supported := range supportedFormats {
		if format == supported {
			return true
		}
	}
	return false
}
