/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

const (
	DefVCContext                = "https://www.w3.org/2018/credentials/v1"
	jsonWebSignature2020Context = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
	bbsBlsSignature2020Context  = "https://w3id.org/security/bbs/v1"
)

// GetContextsFromJSONRaw reads contexts from raw JSON.
func GetContextsFromJSONRaw(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{DefVCContext}, nil
	}

	var ctx struct {
		Context interface{} `json:"@context,omitempty"`
	}

	err := json.Unmarshal(raw, &ctx)
	if err != nil {
		return nil, err
	}

	if ctx.Context == nil {
		return []string{DefVCContext}, nil
	}

	return decodeContext(ctx.Context)
}

// decodeContext decodes raw context(s).
func decodeContext(c interface{}) ([]string, error) {
	switch rContext := c.(type) {
	case string:
		return []string{rContext}, nil
	case []interface{}:
		var s []string

		for i := range rContext {
			c, valid := rContext[i].(string)
			if !valid {
				return nil, fmt.Errorf("unexpected context type")
			}

			s = append(s, c)
		}

		// no contexts of custom type, just string contexts found
		return s, nil
	default:
		return nil, errors.New("credential context of unknown type")
	}
}

// DecodeTypedIDFromJSONRaw decodes verifiable type ID from JSON raw.
func DecodeTypedIDFromJSONRaw(typedIDBytes json.RawMessage) ([]verifiable.TypedID, error) {
	if len(typedIDBytes) == 0 {
		return nil, nil
	}

	var singleTypedID verifiable.TypedID

	err := json.Unmarshal(typedIDBytes, &singleTypedID)
	if err == nil {
		return []verifiable.TypedID{singleTypedID}, nil
	}

	var composedTypedID []verifiable.TypedID

	err = json.Unmarshal(typedIDBytes, &composedTypedID)
	if err == nil {
		return composedTypedID, nil
	}

	return nil, err
}

// UpdateIssuer overrides credential issuer for profile if profile.OverwriteIssuer=true or credential issuer is missing.
// Credential issuer will always be DID.
func UpdateIssuer(credential *verifiable.Credential, issuerDID, issuerName string, overwriteIssuer bool) {
	if overwriteIssuer || credential.Issuer.ID == "" {
		credential.Issuer = verifiable.Issuer{
			ID:           issuerDID,
			CustomFields: verifiable.CustomFields{"name": issuerName},
		}
	}
}

// UpdateSignatureTypeContext updates context for JSONWebSignature2020 and BbsBlsSignature2020.
func UpdateSignatureTypeContext(credential *verifiable.Credential, signatureType vcsverifiable.SignatureType) {
	if signatureType == vcsverifiable.JSONWebSignature2020 {
		credential.Context = append(credential.Context, jsonWebSignature2020Context)
	}

	if signatureType == vcsverifiable.BbsBlsSignature2020 {
		credential.Context = append(credential.Context, bbsBlsSignature2020Context)
	}
}

// PrependCredentialPrefix prepends prefix to credential.ID.
func PrependCredentialPrefix(credential *verifiable.Credential, prefix string) {
	if strings.HasPrefix(credential.ID, prefix) {
		return
	}

	credential.ID = fmt.Sprintf("%s%s", prefix, credential.ID)
}
