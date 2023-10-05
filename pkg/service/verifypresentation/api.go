/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifypresentation

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type Options struct {
	Domain    string
	Challenge string
}

// PresentationVerificationCheckResult resp containing failure check details.
type PresentationVerificationCheckResult struct {
	Check string
	Error string
}

type ServiceInterface interface {
	VerifyPresentation(
		ctx context.Context,
		presentation *verifiable.Presentation,
		opts *Options,
		profile *profileapi.Verifier,
	) ([]PresentationVerificationCheckResult, map[string][]string, error)
}
