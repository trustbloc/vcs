/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"errors"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func ValidateCredential(cred interface{}, formats []vcsverifiable.Format,
	opts ...verifiable.CredentialOpt) (*verifiable.Credential, error) {
	vcBytes, err := vcsverifiable.ValidateFormat(cred, formats)
	if err != nil {
		return nil, err
	}

	// validate the VC (ignore the proof and issuanceDate)
	credential, err := verifiable.ParseCredential(vcBytes, opts...)

	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	if credential.Expired != nil && time.Now().UTC().After(credential.Expired.Time) {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential",
			errors.New("credential expired"))
	}

	return credential, nil
}
