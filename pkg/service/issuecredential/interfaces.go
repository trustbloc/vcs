/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type composer interface {
	Compose(
		ctx context.Context,
		cred *verifiable.Credential,
		req *PrepareCredentialsRequest,
	) (*verifiable.Credential, error)
}

type ServiceInterface interface {
	IssueCredential(
		ctx context.Context,
		credential *verifiable.Credential,
		profile *profileapi.Issuer,
		opts ...Opts,
	) (*verifiable.Credential, error)
}
