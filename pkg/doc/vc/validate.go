/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func ValidateCredential(cred interface{}, formats []vcsverifiable.Format,
	opts ...verifiable.CredentialOpt) (*verifiable.Credential, error) {
	formatMetadata, err := vcsverifiable.ValidateFormat(cred, formats)
	if err != nil {
		return nil, err
	}

	// validate the VC (ignore the proof and issuanceDate)
	credential, err := verifiable.ParseCredential(formatMetadata.Data, opts...)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "credential", err)
	}

	if formatMetadata.Format == vcsverifiable.Jwt && len(formatMetadata.SDJWTDisclosures) > 0 {
		credential.JWT += common.CombinedFormatSeparator + formatMetadata.SDJWTDisclosures
	}

	return credential, nil
}
