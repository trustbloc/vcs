/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/dataprotect"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/verifypresentation"
)

type credentialIssuer interface {
	PrepareCredential(
		ctx context.Context,
		req *issuecredential.PrepareCredentialsRequest,
	) (*verifiable.Credential, error)
}

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

type claimDataStore interface {
	Create(ctx context.Context, profileTTLSec int32, data *issuecredential.ClaimData) (string, error)
	GetAndDelete(ctx context.Context, id string) (*issuecredential.ClaimData, error)
}

type dataProtector interface {
	Encrypt(ctx context.Context, msg []byte) (*dataprotect.EncryptedData, error)
	Decrypt(ctx context.Context, encryptedData *dataprotect.EncryptedData) ([]byte, error)
}

type transactionStore1 interface {
	Create(
		ctx context.Context,
		profileTransactionDataTTL int32,
		data *issuecredential.TransactionData,
	) (*issuecredential.Transaction, error)

	FindByOpState(
		ctx context.Context,
		opState string,
	) (*issuecredential.Transaction, error)
}
