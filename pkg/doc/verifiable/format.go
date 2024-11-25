/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
)

type OIDCFormat string

type Format string

type Model string

const (
	V1_1 Model = "w3c-vc-1.1"
	V2_0 Model = "w3c-vc-2.0"
)

// For mapping between Format and OIDCFormat see oidc4ci.SelectProperOIDCFormat.
const (
	Jwt Format = "jwt"
	Ldp Format = "ldp"
	Cwt Format = "cwt"
)

const (
	JwtVCJsonLD OIDCFormat = "jwt_vc_json-ld"
	CwtVcLD     OIDCFormat = "cwt_vc-ld"
	JwtVCJson   OIDCFormat = "jwt_vc_json"
	LdpVC       OIDCFormat = "ldp_vc"
)

func ValidateFormat(data interface{}, formats []Format) ([]byte, error) {
	strRep, isStr := data.(string)

	if !isStr {
		if mapped, ok := data.(*string); ok {
			strRep = *mapped
			isStr = true
		}
	}

	var dataBytes []byte

	if isStr {
		if !isFormatSupported(Jwt, formats) {
			return nil, fmt.Errorf("invalid format, should be %s", Jwt)
		}

		dataBytes = []byte(strRep)
	}

	if !isStr {
		if !isFormatSupported(Ldp, formats) {
			return nil, fmt.Errorf("invalid format, should be %s", Ldp)
		}

		var err error
		dataBytes, err = json.Marshal(data)

		if err != nil {
			return nil, fmt.Errorf("invlaid format: %w", err)
		}
	}

	return dataBytes, nil
}

func isFormatSupported(format Format, supportedFormats []Format) bool {
	for _, supported := range supportedFormats {
		if format == supported {
			return true
		}
	}
	return false
}
