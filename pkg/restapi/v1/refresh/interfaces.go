/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh

import (
	"context"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/refresh"
)

//go:generate mockgen -destination interfaces_mocks_test.go -package refresh_test -source=interfaces.go

// ProfileService defines issuer profile service interface.
type ProfileService interface {
	GetProfile(profileID profileapi.ID, profileVersion profileapi.Version) (*profileapi.Issuer, error)
}

// CredentialRefreshService defines credential refresh service interface.
type CredentialRefreshService interface {
	RequestRefreshStatus(
		ctx context.Context,
		credentialID string,
		issuer profileapi.Issuer,
	) (*refresh.GetRefreshStateResponse, error)

	GetRefreshedCredential(
		ctx context.Context,
		presentation *verifiable.Presentation,
		issuer profileapi.Issuer,
	) (*verifiable.Credential, error)
}

type ProofChecker interface {
	CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error

	// GetLDPCanonicalDocument will return normalized/canonical version of the document
	GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetLDPDigest returns document digest
	GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error)

	CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error
	CheckCWTProof(
		checkCWTRequest checker.CheckCWTProofRequest,
		expectedProofIssuer string,
		msg []byte,
		signature []byte,
	) error
}
