package oidc4ci

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

//go:generate mockgen -destination interfaces_mocks_test.go -package oidc4ci_test -source=interfaces.go

type credentialIssuer interface {
	PrepareCredential(
		ctx context.Context,
		req *issuecredential.PrepareCredentialsRequest,
	) (*verifiable.Credential, error)
}

type composer interface { // nolint:unused
	Compose(
		ctx context.Context,
		cred *verifiable.Credential,
		req *issuecredential.PrepareCredentialsRequest,
	) (*verifiable.Credential, error)
}
