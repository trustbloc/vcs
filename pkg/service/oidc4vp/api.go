/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"context"

	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

type InteractionInfo struct {
	AuthorizationRequest string
	TxID                 TxID
}

type ProcessedVPToken struct {
	Nonce         string
	ClientID      string
	SignerDIDID   string
	VpTokenFormat vcsverifiable.Format
	Presentation  *verifiable.Presentation
}

type CredentialMetadata struct {
	Format         vcsverifiable.Format `json:"format"`
	Type           []string             `json:"type"`
	SubjectData    interface{}          `json:"subjectData"`
	Issuer         interface{}          `json:"issuer"`
	IssuanceDate   *util.TimeWrapper    `json:"issuanceDate,omitempty"`
	ExpirationDate *util.TimeWrapper    `json:"expirationDate,omitempty"`
}

type ServiceInterface interface {
	InitiateOidcInteraction(
		ctx context.Context,
		presentationDefinition *presexch.PresentationDefinition,
		purpose string,
		profile *profileapi.Verifier,
	) (*InteractionInfo, error)
	VerifyOIDCVerifiablePresentation(ctx context.Context, txID TxID, token []*ProcessedVPToken) error
	GetTx(ctx context.Context, id TxID) (*Transaction, error)
	RetrieveClaims(ctx context.Context, tx *Transaction, profile *profileapi.Verifier) map[string]CredentialMetadata
	DeleteClaims(ctx context.Context, receivedClaimsID string) error
}

type EventPayload struct {
	WebHook                  string  `json:"webHook,omitempty"`
	ProfileID                string  `json:"profileID,omitempty"`
	ProfileVersion           string  `json:"profileVersion,omitempty"`
	OrgID                    string  `json:"orgID,omitempty"`
	PresentationDefinitionID string  `json:"presentationDefinitionID,omitempty"`
	Filter                   *Filter `json:"filter,omitempty"`
	AuthorizationRequest     string  `json:"authorizationRequest,omitempty"`
	Error                    string  `json:"error,omitempty"`
	ErrorCode                string  `json:"errorCode"`
	ErrorComponent           string  `json:"errorComponent,omitempty"`
}

type Filter struct {
	Fields []string `json:"fields"`
}

type TxNonceStore txNonceStore

type TxClaimsStore txClaimsStore

type TxStoreStore txStore
