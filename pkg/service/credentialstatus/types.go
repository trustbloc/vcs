/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

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
type CSL verifiable.Credential

// CSLWrapper contains CSL and metadata.
type CSLWrapper struct {
	// VCByte stores the CSL.
	VCByte json.RawMessage `json:"vc,omitempty"`
	// UsedIndexes stores the list of used bit indexes in the CSL encoded list.
	UsedIndexes []int `json:"usedIndexes"`
	// VC represents parsed CSL.
	VC *verifiable.Credential `json:"-"`
	// Version represents the version of the CSLWrapper.
	Version int `json:"version,omitempty"`
}

type UpdateVCStatusParams struct {
	// Issuer Profile ID.
	ProfileID profileapi.ID
	// ID of the verifiable.Credential, that supposed to get updated status to DesiredStatus.
	CredentialID string
	// Desired status of the verifiable.Credential referenced by CredentialID.
	// Values are validated using strconv.ParseBool func.
	DesiredStatus string
	// vc.StatusType of verifiable.Credential referenced by CredentialID.
	StatusType vc.StatusType
}

type StatusListEntry struct {
	Context string
	TypedID *verifiable.TypedID
}

type ServiceInterface interface {
	CreateStatusListEntry(ctx context.Context, profileID, credentialID string) (*StatusListEntry, error)
	GetStatusListVC(ctx context.Context, profileID profileapi.ID, statusID string) (*verifiable.Credential, error)
	UpdateVCStatus(ctx context.Context, params UpdateVCStatusParams) error
	Resolve(ctx context.Context, statusListVCURI string) (*verifiable.Credential, error)
}

// UpdateCredentialStatusEventPayload represents the event payload for credential status update.
// Corresponding event type is spi.CredentialStatusStatusUpdated.
type UpdateCredentialStatusEventPayload struct {
	CSLURL    string `json:"cslurl"`
	ProfileID string `json:"profileId"`
	Index     int    `json:"index"`
	Status    bool   `json:"status"`
	Version   int    `json:"version"`
}
