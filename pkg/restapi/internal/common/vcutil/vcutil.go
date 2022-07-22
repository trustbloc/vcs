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

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/vcs/pkg/doc/vc/profile"
)

const (
	defVCContext                = "https://www.w3.org/2018/credentials/v1"
	jsonWebSignature2020Context = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
	bbsBlsSignature2020Context  = "https://w3id.org/security/bbs/v1"
)

// GetContextsFromJSONRaw reads contexts from raw JSON.
func GetContextsFromJSONRaw(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{defVCContext}, nil
	}

	var ctx struct {
		Context interface{} `json:"@context,omitempty"`
	}

	err := json.Unmarshal(raw, &ctx)
	if err != nil {
		return nil, err
	}

	if ctx.Context == nil {
		return []string{defVCContext}, nil
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
func UpdateIssuer(credential *verifiable.Credential, profile *vcprofile.IssuerProfile) {
	if profile.OverwriteIssuer || credential.Issuer.ID == "" {
		credential.Issuer = verifiable.Issuer{
			ID:           profile.DID,
			CustomFields: verifiable.CustomFields{"name": profile.Name},
		}
	}
}

// UpdateSignatureTypeContext updates context for JSONWebSignature2020.
func UpdateSignatureTypeContext(credential *verifiable.Credential, profile *vcprofile.IssuerProfile) {
	if profile.SignatureType == crypto.JSONWebSignature2020 {
		credential.Context = append(credential.Context, jsonWebSignature2020Context)
	}

	if profile.SignatureType == crypto.BbsBlsSignature2020 {
		credential.Context = append(credential.Context, bbsBlsSignature2020Context)
	}
}

// GetDocIDFromURL Given an EDV document URL, returns just the document ID.
func GetDocIDFromURL(docURL string) string {
	splitBySlashes := strings.Split(docURL, `/`)
	docIDToRetrieve := splitBySlashes[len(splitBySlashes)-1]

	return docIDToRetrieve
}

// GetVaultIDFromURL Given an EDV vault location URL, returns just the vaultID.
func GetVaultIDFromURL(vaultLocationURL string) string {
	vaultLocationURLSplitUp := strings.Split(vaultLocationURL, "/")

	return vaultLocationURLSplitUp[len(vaultLocationURLSplitUp)-1]
}
