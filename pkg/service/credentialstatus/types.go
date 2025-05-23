/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

var (
	ErrDataNotFound = errors.New("data not found")
)

// CSL (Credential Status List) - is a verifiable.Credential that stores the
// revocation status of credentials issued by Issuer.
//
//	This type is created for the documentation purpose.
type CSL = verifiable.Credential

// CSLIndexWrapper contains CSL Indexes and Version.
type CSLIndexWrapper struct {
	CSLURL string `json:"_id" bson:"_id"`

	ListID ListID `json:"listID"`

	// UsedIndexes stores the list of used bit indexes in the CSL encoded list.
	UsedIndexes []int `json:"usedIndexes"`

	ProfileGroupID string `json:"profileGroupID"`

	Status string `json:"status"`

	OwnerID string `json:"ownerID"`
}

// CSLVCWrapper contains CSL VC and version.
type CSLVCWrapper struct {
	// VCByte stores the CSL.
	VCByte json.RawMessage `json:"vc,omitempty"`
	// VC represents parsed CSL VC. Not stored.
	VC *verifiable.Credential `json:"-"`
}

type UpdateVCStatusParams struct {
	// Client roles from oAuth provider.
	OAuthClientRoles []string
	// Issuer Profile ID.
	ProfileID profileapi.ID
	// Issuer Profile Version.
	ProfileVersion profileapi.Version
	// ID of the verifiable.Credential, that supposed to get updated status to DesiredStatus.
	CredentialID string
	// Desired status of the verifiable.Credential referenced by CredentialID.
	// Values are validated using strconv.ParseBool func.
	DesiredStatus string
	// vc.StatusType of verifiable.Credential referenced by CredentialID.
	StatusType vc.StatusType
	// StatusPurpose specifies the purpose of the status update, e.g. "revocation", "suspension".
	StatusPurpose string
}

type StatusListEntry struct {
	Context string
	TypedID *verifiable.TypedID
}

type ServiceInterface interface {
	CreateStatusListEntry(
		ctx context.Context,
		profileID profileapi.ID,
		profileVersion profileapi.Version,
		credentialID string,
		statusPurpose string,
	) (*StatusListEntry, error)
	StoreIssuedCredentialMetadata(
		ctx context.Context,
		profileID profileapi.ID,
		profileVersion profileapi.Version,
		metadata *CredentialMetadata,
	) error
	GetStatusListVC(ctx context.Context, profileGroupID profileapi.ID, statusID string) (*CSL, error)
	UpdateVCStatus(ctx context.Context, params UpdateVCStatusParams) error // oidc4cierr.Error
	Resolve(ctx context.Context, statusListVCURI string) (*CSL, error)
}

// UpdateCredentialStatusEventPayload represents the event payload for credential status update.
// Corresponding event type is spi.CredentialStatusStatusUpdated.
type UpdateCredentialStatusEventPayload struct {
	CSLURL         string `json:"cslurl"`
	ProfileID      string `json:"profileId"`
	ProfileVersion string `json:"profileVersion"`
	Index          int    `json:"index"`
	Status         bool   `json:"status"`
}

// CredentialMetadata represents the credential metadata.
type CredentialMetadata struct {
	CredentialID   string            `json:"credential"`
	Issuer         string            `json:"issuer,omitempty"`
	ProfileVersion string            `json:"profile_version,omitempty"`
	CredentialType []string          `json:"credentialType,omitempty"`
	TransactionID  string            `json:"transactionId,omitempty"`
	IssuanceDate   *time.TimeWrapper `json:"issuanceDate,omitempty"`
	ExpirationDate *time.TimeWrapper `json:"expirationDate,omitempty"`
}
