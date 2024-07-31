package oidc4ci

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

type presentationVerifier interface {
	VerifyPresentation(
		ctx context.Context,
		presentation *verifiable.Presentation,
		opts *verifypresentation.Options,
		profile *profileapi.Verifier,
	) (
		[]verifypresentation.PresentationVerificationCheckResult, map[string][]string, error,
	)
}

type credentialIssuer interface {
	PrepareCredential(
		ctx context.Context,
		tx *Transaction,
		txCredentialConfiguration *TxCredentialConfiguration,
		prepareCredentialRequest *PrepareCredentialRequest,
	)
}
