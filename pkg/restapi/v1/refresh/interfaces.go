/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh

import (
	"context"

	"github.com/trustbloc/vc-go/verifiable"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/refresh"
)

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
