/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vp

import (
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

func ValidatePresentation(pres interface{}, formats []vcsverifiable.Format,
	opts ...verifiable.PresentationOpt) (*verifiable.Presentation, error) {
	vpBytes, err := vcsverifiable.ValidateFormat(pres, formats)
	if err != nil {
		return nil, err
	}

	presentation, err := verifiable.ParsePresentation(vpBytes, opts...)
	if err != nil {
		return nil, fmt.Errorf("parse presentation: %w", err)
	}

	return presentation, nil
}
