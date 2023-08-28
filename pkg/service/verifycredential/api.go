/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifycredential

import (
	"context"

	"github.com/hyperledger/aries-framework-go/component/models/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

// CredentialsVerificationCheckResult resp containing failure check details.
type CredentialsVerificationCheckResult struct {
	Check              string
	Error              string
	VerificationMethod string
}

// Options represents options for verify credential.
type Options struct {
	// Challenge is added to the proof.
	Challenge string

	// Domain is added to the proof.
	Domain string
}

type ServiceInterface interface {
	VerifyCredential(
		ctx context.Context,
		credential *verifiable.Credential,
		opts *Options,
		profile *profileapi.Verifier,
	) ([]CredentialsVerificationCheckResult, error)

	ValidateCredentialProof(
		ctx context.Context,
		vcByte []byte,
		proofChallenge, proofDomain string,
		vcInVPValidation, isJWT bool,
	) error

	ValidateVCStatus(ctx context.Context, vcStatus *verifiable.TypedID, issuer string) error

	ValidateLinkedDomain(ctx context.Context, signingDID string) error
}
