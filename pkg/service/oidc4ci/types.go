package oidc4ci

import (
	"github.com/trustbloc/vc-go/presexch"

	"github.com/trustbloc/vcs/pkg/profile"
)

type CreateRefreshStateRequest struct {
	CredentialID string
	Issuer       profile.Issuer
	Claims       map[string]interface{}

	CredentialName        *string
	CredentialDescription *string
}

type GetRefreshStateResponse struct {
	VerifiablePresentationRequest VerifiablePresentationRequest `json:"verifiablePresentationRequest"`
	Challenge                     string                        `json:"challenge"`
	Domain                        string                        `json:"domain"`
	RefreshServiceType            RefreshServiceType            `json:"refreshServiceType"`
}

type RefreshServiceType struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Interact struct {
	Interact []InteractService `json:"interact"`
}

type InteractService struct {
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type VerifiablePresentationRequest struct {
	Query presexch.PresentationDefinition `json:"query"`
}
