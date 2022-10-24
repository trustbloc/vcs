package privateapi

import (
	"net/url"

	"github.com/ory/fosite"
)

type PrepareClaimDataAuthZRequest struct {
	OpState   string                `json:"op_state"`
	Responder PrepareClaimResponder `json:"responder"`
}

type PrepareClaimResponder struct {
	RedirectURI       *url.URL                 `json:"redirect_uri"`
	RespondMode       fosite.ResponseModeType  `json:"respond_mode"`
	AuthorizeResponse fosite.AuthorizeResponse `json:"authorize_response"`
}

type PrepareClaimDataAuthZResponse struct {
	RedirectURI string `json:"redirect_uri"`
}
