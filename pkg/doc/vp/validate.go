/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func ValidatePresentation(pres interface{}, formats []vcsverifiable.Format,
	opts ...verifiable.PresentationOpt) (*verifiable.Presentation, error) {
	formatMetadata, err := vcsverifiable.ValidateFormat(pres, formats)
	if err != nil {
		return nil, err
	}

	presentation, err := verifiable.ParsePresentation(formatMetadata.Data, opts...)
	if err != nil {
		return nil, resterr.NewValidationError(resterr.InvalidValue, "presentation", err)
	}

	return presentation, nil
}
