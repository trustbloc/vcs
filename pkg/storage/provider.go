/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"encoding/json"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
)

// Provider is a storage provider that allows for VCS storage functionality.
// Using a Provider, a caller can open stores for storage of specific types of data.
type Provider interface {
	OpenMasterKeyStore() (MasterKeyStore, error)
	OpenHolderProfileStore() (HolderProfileStore, error)
	OpenIssuerProfileStore() (IssuerProfileStore, error)
	OpenVerifierProfileStore() (VerifierProfileStore, error)
	OpenCSLStore() (CSLStore, error)
	OpenVCStore() (VCStore, error)
	GetAriesProvider() ariesstorage.Provider
}

type MasterKeyStore interface {
	Put(masterKey []byte) error
	Get() ([]byte, error)
}

type HolderProfileStore interface {
	Put(profile HolderProfile) error
	Get(name string) (HolderProfile, error)
	Delete(name string) error
}

type IssuerProfileStore interface {
	Put(profile IssuerProfile) error
	Get(name string) (IssuerProfile, error)
	Delete(name string) error
}

type VerifierProfileStore interface {
	Put(profile VerifierProfile) error
	Get(id string) (VerifierProfile, error)
	Delete(name string) error
}

type CSLStore interface {
	PutCSLWrapper(cslWrapper *CSLWrapper) error
	GetCSLWrapper(id string) (*CSLWrapper, error)
	UpdateLatestListID(id int) error
	GetLatestListID() (int, error)
}

type VCStore interface {
	Put(profileName string, vc *verifiable.Credential) error
	Get(profileName, vcID string) ([]byte, error)
}

type HolderProfile struct {
	OverwriteHolder bool `json:"overwriteHolder,omitempty"`
	DataProfile
}

type IssuerProfile struct {
	URI             string `json:"uri,omitempty"`
	DisableVCStatus bool   `json:"disableVCStatus,omitempty"`
	OverwriteIssuer bool   `json:"overwriteIssuer,omitempty"`
	DataProfile
}

type VerifierProfile struct {
	// profile id - avoid using special characters or whitespaces
	// required: true
	ID string `json:"id,omitempty"`
	// verifier name
	// required: true
	Name string `json:"name,omitempty"`
	// credential verification checks - supported options: proof and status
	CredentialChecks []string `json:"credentialChecks,omitempty"`
	// presentation verification checks - supported options: proof
	PresentationChecks []string `json:"presentationChecks,omitempty"`
}

// DataProfile is the base profile for issuers and holders.
type DataProfile struct {
	Name                    string                             `json:"name,omitempty"`
	DID                     string                             `json:"did,omitempty"`
	SignatureType           string                             `json:"signatureType,omitempty"`
	SignatureRepresentation verifiable.SignatureRepresentation `json:"signatureRepresentation,omitempty"`
	Creator                 string                             `json:"creator,omitempty"`
	Created                 *time.Time                         `json:"created,omitempty"`
}

// CSLWrapper contains CSL and metadata.
type CSLWrapper struct {
	VCByte              json.RawMessage        `json:"vc"`
	Size                int                    `json:"size"`
	RevocationListIndex int                    `json:"revocationListIndex"`
	ListID              int                    `json:"listID"`
	VC                  *verifiable.Credential `json:"-"`
}
