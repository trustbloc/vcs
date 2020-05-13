/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddoc

import (
	"fmt"
	"strings"
)

const (
	creatorParts = 2

	invalidFormatErrMsgFmt = "verificationMethod value %s should be in did#keyID format"
)

// GetDIDFromVerificationMethod fetches did from the verification method.
func GetDIDFromVerificationMethod(creator string) (string, error) {
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(fmt.Sprintf(invalidFormatErrMsgFmt, creator))
	}

	return idSplit[0], nil
}

// GetKeyIDFromVerificationMethod fetches keyid from the verification method.
func GetKeyIDFromVerificationMethod(creator string) (string, error) {
	idSplit := strings.Split(creator, "#")
	if len(idSplit) != creatorParts {
		return "", fmt.Errorf(fmt.Sprintf(invalidFormatErrMsgFmt, creator))
	}

	return idSplit[1], nil
}
