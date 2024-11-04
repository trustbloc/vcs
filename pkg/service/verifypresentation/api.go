/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifypresentation

import (
	"context"

	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type Options struct {
	Domain    string
	Challenge string
}

// PresentationVerificationResult resp containing failure check details.
type PresentationVerificationResult struct {
	Checks []*Check
}

func (r *PresentationVerificationResult) HasErrors() bool {
	return len(r.Errors()) > 0
}

func (r *PresentationVerificationResult) Errors() []*Check {
	var checks []*Check

	for _, check := range r.Checks {
		if !lo.IsNil(check.Error) {
			checks = append(checks, check)
		}
	}

	return checks
}

type Check struct {
	Check string
	Error error
}

type ServiceInterface interface {
	VerifyPresentation(
		ctx context.Context,
		presentation *verifiable.Presentation,
		opts *Options,
		profile *profileapi.Verifier,
	) (PresentationVerificationResult, map[string][]string, error)
}
