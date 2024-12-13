/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddoc

import (
	"fmt"
	"strings"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

const (
	creatorParts = 2

	invalidFormatErrMsgFmt = "verificationMethod value %s should be in did#keyID format"
)

// GetDIDFromVerificationMethod fetches did from the verification method.
func GetDIDFromVerificationMethod(creator string) (string, error) {
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(invalidFormatErrMsgFmt, creator)
	}

	return idSplit[0], nil
}

// GetKeyIDFromVerificationMethod fetches keyid from the verification method.
func GetKeyIDFromVerificationMethod(creator string) (string, error) {
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(invalidFormatErrMsgFmt, creator)
	}

	return idSplit[1], nil
}

func GetDIDDocFromVerificationMethod(verificationMethod string, vdr vdrapi.Registry) (*did.Doc, error) {
	didID, err := GetDIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, err
	}

	docResolution, err := vdr.Resolve(didID)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
}
