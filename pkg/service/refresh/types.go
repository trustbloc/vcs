package refresh

import (
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

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
	RefreshServiceType            ServiceType                   `json:"refreshServiceType"`
}

type GetRefreshedCredentialResponse struct {
	Credential *verifiable.Credential
	IssuerURL  string
}

type Event struct {
	WebHook        string `json:"webHook,omitempty"`
	ProfileID      string `json:"profileID,omitempty"`
	ProfileVersion string `json:"profileVersion,omitempty"`
	OrgID          string `json:"orgID,omitempty"`

	Error          string `json:"error,omitempty"`
	ErrorCode      string `json:"errorCode,omitempty"`
	ErrorComponent string `json:"errorComponent,omitempty"`
}

type ServiceType struct {
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
