/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"context"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type ServiceInterface interface {
	IssueCredential(
		ctx context.Context,
		credential *verifiable.Credential,
		issuerSigningOpts []crypto.SigningOpts,
		profile *profileapi.Issuer,
	) (*verifiable.Credential, error)
}
