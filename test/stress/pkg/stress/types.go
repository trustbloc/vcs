package stress

import "time"

type Result struct {
	UserCount          int                           `json:"user_count"`
	ConcurrentRequests int                           `json:"concurrent_requests"`
	Metrics            []*Metric                     `json:"metrics"`
	TotalDuration      time.Duration                 `json:"total_duration"`
	Errors             []error                       `json:"-"`
	PerCredentialData  map[string]*PerCredentialData `json:"per_credential_data"`
}

type Metric struct {
	Name string
	Avg  time.Duration
	Max  time.Duration
	Min  time.Duration
}

type initiateOIDC4CIRequest struct {
	ClaimData                 *map[string]interface{} `json:"claim_data,omitempty"`
	ClaimEndpoint             string                  `json:"claim_endpoint,omitempty"`
	ClientInitiateIssuanceUrl string                  `json:"client_initiate_issuance_url,omitempty"`
	ClientWellknown           string                  `json:"client_wellknown,omitempty"`
	CredentialTemplateId      string                  `json:"credential_template_id,omitempty"`
	GrantType                 string                  `json:"grant_type,omitempty"`
	OpState                   string                  `json:"op_state,omitempty"`
	ResponseType              string                  `json:"response_type,omitempty"`
	Scope                     []string                `json:"scope,omitempty"`
	UserPinRequired           bool                    `json:"user_pin_required,omitempty"`
}

type initiateOIDC4CIResponse struct {
	OfferCredentialURL string  `json:"offer_credential_url"`
	TxId               string  `json:"tx_id"`
	UserPin            *string `json:"user_pin"`
}

type initiateOIDC4VPResponse struct {
	AuthorizationRequest string `json:"authorizationRequest"`
	TxID                 string `json:"txID"`
}

type PerCredentialData struct {
	Metrics map[string]string `json:"metrics"`
	Error   string            `json:"error"`
}

// initiateOIDC4VPData defines model for InitiateOIDC4VPData.
type initiateOIDC4VPData struct {
	PresentationDefinitionId *string `json:"presentationDefinitionId,omitempty"`
}
