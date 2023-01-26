/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

// InitiateIssuance creates credential issuance transaction and builds initiate issuance URL.
func (s *Service) InitiateIssuance(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) (*InitiateIssuanceResponse, error) {
	if !profile.Active {
		return nil, ErrProfileNotActive
	}

	if profile.VCConfig == nil {
		return nil, ErrVCOptionsNotConfigured
	}

	isPreAuthorizeFlow := len(req.ClaimData) > 0
	if !isPreAuthorizeFlow && profile.OIDCConfig == nil {
		return nil, ErrAuthorizedCodeFlowNotSupported
	}

	var template *profileapi.CredentialTemplate

	if req.CredentialTemplateID == "" {
		if len(profile.CredentialTemplates) > 1 {
			return nil, errors.New("credential template should be specified")
		}
		template = profile.CredentialTemplates[0]
	} else {
		credTemplate, err := findCredentialTemplate(profile.CredentialTemplates, req.CredentialTemplateID)
		if err != nil {
			return nil, err
		}
		template = credTemplate
	}

	data := &TransactionData{
		ProfileID:          profile.ID,
		OrgID:              profile.OrganizationID,
		CredentialTemplate: template,
		CredentialFormat:   profile.VCConfig.Format,
		ClaimEndpoint:      req.ClaimEndpoint,
		GrantType:          req.GrantType,
		ResponseType:       req.ResponseType,
		Scope:              req.Scope,
		OpState:            req.OpState,
		ClaimData:          req.ClaimData,
		State:              TransactionStateIssuanceInitiated,
		WebHookURL:         profile.WebHook,
	}

	if err := s.extendTransactionWithOIDCConfig(ctx, profile, data); err != nil {
		return nil, err
	}

	if data.GrantType == "" {
		data.GrantType = defaultGrantType
	}
	if data.ResponseType == "" {
		data.ResponseType = defaultResponseType
	}
	if len(data.Scope) == 0 {
		data.Scope = []string{defaultScope}
	}
	if len(data.ClaimData) > 0 {
		data.IsPreAuthFlow = isPreAuthorizeFlow
		data.PreAuthCode = generatePreAuthCode()
		data.OpState = data.PreAuthCode // set opState as it will be empty for pre-auth
	}

	tx, err := s.store.Create(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("store tx: %w", err)
	}

	if req.UserPinRequired {
		data.UserPin = s.pinGenerator.Generate(string(tx.ID))
		tx.UserPin = data.UserPin

		err = s.store.Update(ctx, tx)
		if err != nil {
			return nil, fmt.Errorf("store pin tx: %w", err)
		}
	}

	if errSendEvent := s.sendEvent(tx, spi.IssuerOIDCInteractionInitiated); errSendEvent != nil {
		return nil, errSendEvent
	}

	return &InitiateIssuanceResponse{
		InitiateIssuanceURL: s.buildInitiateIssuanceURL(ctx, req, template, tx),
		TxID:                tx.ID,
		UserPin:             tx.UserPin,
	}, nil
}

func (s *Service) extendTransactionWithOIDCConfig(
	ctx context.Context,
	profile *profileapi.Issuer,
	data *TransactionData,
) error {
	if profile.OIDCConfig == nil { // optional for pre-authorize, must have for authorize flow
		return nil
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return fmt.Errorf("get oidc configuration from well-known: %w", err)
	}

	data.AuthorizationEndpoint = oidcConfig.AuthorizationEndpoint
	data.PushedAuthorizationRequestEndpoint = oidcConfig.PushedAuthorizationRequestEndpoint
	data.TokenEndpoint = oidcConfig.TokenEndpoint

	data.ClientID = profile.OIDCConfig.ClientID
	data.ClientSecret = profile.OIDCConfig.ClientSecretHandle
	data.Scope = profile.OIDCConfig.Scope
	data.RedirectURI = profile.OIDCConfig.RedirectURI

	return nil
}

func generatePreAuthCode() string {
	return uuid.NewString() + fmt.Sprint(time.Now().UnixNano())
}

func findCredentialTemplate(
	credentialTemplates []*profileapi.CredentialTemplate,
	templateID string,
) (*profileapi.CredentialTemplate, error) {
	// profile should define at least one credential template
	if len(credentialTemplates) == 0 || credentialTemplates[0].ID == "" {
		return nil, ErrCredentialTemplateNotConfigured
	}

	// credential template ID is required if profile has more than one credential template defined
	if len(credentialTemplates) > 1 && templateID == "" {
		return nil, ErrCredentialTemplateIDRequired
	}

	for _, t := range credentialTemplates {
		if t.ID == templateID {
			return t, nil
		}
	}

	return nil, ErrCredentialTemplateNotFound
}

func (s *Service) buildInitiateIssuanceURL(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	template *profileapi.CredentialTemplate,
	tx *Transaction,
) string {
	var initiateIssuanceURL string

	if req.ClientInitiateIssuanceURL != "" {
		initiateIssuanceURL = req.ClientInitiateIssuanceURL
	} else if req.ClientWellKnownURL != "" {
		c, err := s.wellKnownService.GetOIDCConfiguration(ctx, req.ClientWellKnownURL)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get OIDC configuration from well-known %q", req.ClientWellKnownURL),
				log.WithError(err))
		} else {
			initiateIssuanceURL = c.InitiateIssuanceEndpoint
		}
	}

	if initiateIssuanceURL == "" {
		initiateIssuanceURL = "openid-initiate-issuance://"
	}

	q := url.Values{}
	q.Set("credential_type", template.Type)

	issuerURL, _ := url.JoinPath(s.issuerVCSPublicHost, "issuer", tx.ProfileID)

	if tx.IsPreAuthFlow {
		q.Set("issuer", issuerURL)
		q.Set("pre-authorized_code", tx.PreAuthCode)
		q.Set("user_pin_required", strconv.FormatBool(req.UserPinRequired))
	} else {
		q.Set("issuer", issuerURL)
		q.Set("op_state", req.OpState)
	}

	return initiateIssuanceURL + "?" + q.Encode()
}
