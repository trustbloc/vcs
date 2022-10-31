/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/trustbloc/vcs/internal/pkg/log"
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

	if profile.OIDCConfig == nil {
		return nil, ErrAuthorizedCodeFlowNotSupported
	}

	if profile.VCConfig == nil {
		return nil, ErrVCOptionsNotConfigured
	}

	template, err := findCredentialTemplate(profile.CredentialTemplates, req.CredentialTemplateID)
	if err != nil {
		return nil, err
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("get oidc configuration from well-known: %w", err)
	}

	data := &TransactionData{
		CredentialTemplate:                 template,
		CredentialFormat:                   profile.VCConfig.Format,
		AuthorizationEndpoint:              oidcConfig.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: oidcConfig.PushedAuthorizationRequestEndpoint,
		TokenEndpoint:                      oidcConfig.TokenEndpoint,
		ClaimEndpoint:                      req.ClaimEndpoint,
		ClientID:                           profile.OIDCConfig.ClientID,
		GrantType:                          req.GrantType,
		ResponseType:                       req.ResponseType,
		Scope:                              req.Scope,
		OpState:                            req.OpState,
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

	tx, err := s.store.Create(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("store tx: %w", err)
	}

	return &InitiateIssuanceResponse{
		InitiateIssuanceURL: s.buildInitiateIssuanceURL(ctx, req, template, tx.ID),
		TxID:                tx.ID,
	}, nil
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
	txID TxID,
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
	q.Set("issuer", s.issuerVCSPublicHost+"/"+string(txID))
	q.Set("credential_type", template.Type)
	q.Set("op_state", req.OpState)

	return initiateIssuanceURL + "?" + q.Encode()
}
