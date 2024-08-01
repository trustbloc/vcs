package oidc4ci

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

//go:generate mockgen -destination interfaces_mocks_test.go -package oidc4ci_test -source=interfaces.go
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
		req *PrepareCredentialsRequest,
	) (*verifiable.Credential, error)
}

type composer interface {
	Compose(
		ctx context.Context,
		cred *verifiable.Credential,
		req *PrepareCredentialsRequest,
	) (*verifiable.Credential, error)
}
