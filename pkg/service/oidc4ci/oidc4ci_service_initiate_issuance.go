/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/event/spi"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

// InitiateIssuance creates credential issuance transaction and builds initiate issuance URL.
func (s *Service) InitiateIssuance(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	profile *profileapi.Issuer,
) (*InitiateIssuanceResponse, error) {
	if req.OpState == "" {
		req.OpState = uuid.NewString()
	}
	if !profile.Active {
		return nil, ErrProfileNotActive
	}
	if profile.OIDCConfig == nil {
		return nil, ErrAuthorizedCodeFlowNotSupported
	}
	if profile.VCConfig == nil {
		return nil, ErrVCOptionsNotConfigured
	}

	template, err := s.findCredentialTemplate(req.CredentialTemplateID, profile)
	if err != nil {
		return nil, err
	}

	oidcConfig, err := s.wellKnownService.GetOIDCConfiguration(ctx, profile.OIDCConfig.IssuerWellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("get oidc configuration from well-known: %w", err)
	}
	data := &TransactionData{
		ProfileID:                          profile.ID,
		CredentialTemplate:                 template,
		CredentialFormat:                   profile.VCConfig.Format,
		AuthorizationEndpoint:              oidcConfig.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: oidcConfig.PushedAuthorizationRequestEndpoint,
		TokenEndpoint:                      oidcConfig.TokenEndpoint,
		ClaimEndpoint:                      req.ClaimEndpoint,
		ClientID:                           profile.OIDCConfig.ClientID,
		ClientSecret:                       profile.OIDCConfig.ClientSecretHandle,
		ClientScope:                        profile.OIDCConfig.Scope,
		RedirectURI:                        profile.OIDCConfig.RedirectURI,
		GrantType:                          req.GrantType,
		ResponseType:                       req.ResponseType,
		Scope:                              req.Scope,
		OpState:                            req.OpState,
		ClaimData:                          req.ClaimData,
		State:                              TransactionStateIssuanceInitiated,
		WebHookURL:                         profile.WebHook,
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
		data.IsPreAuthFlow = true
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

	credentialOffer, err := s.prepareCredentialOffer(ctx, req, template, tx)
	if err != nil {
		return nil, err
	}

	var remoteOfferURL string
	if s.credentialOfferReferenceStore != nil {
		remoteURL, remoteErr := s.credentialOfferReferenceStore.Create(ctx, credentialOffer)
		if remoteErr != nil {
			return nil, remoteErr
		}

		remoteOfferURL = remoteURL
	}

	finalURL, err := s.buildInitiateIssuanceURL(ctx, req, remoteOfferURL, credentialOffer)
	if err != nil {
		return nil, err
	}

	return &InitiateIssuanceResponse{
		InitiateIssuanceURL: finalURL,
		TxID:                tx.ID,
		UserPin:             tx.UserPin,
	}, nil
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

func (s *Service) findCredentialTemplate(
	requestedTemplateID string,
	profile *profileapi.Issuer,
) (*profileapi.CredentialTemplate, error) {
	if requestedTemplateID != "" {
		return findCredentialTemplate(profile.CredentialTemplates, requestedTemplateID)
	}

	if len(profile.CredentialTemplates) > 1 {
		return nil, errors.New("credential template should be specified")
	}

	return profile.CredentialTemplates[0], nil
}

func (s *Service) prepareCredentialOffer(
	_ context.Context,
	req *InitiateIssuanceRequest,
	template *profileapi.CredentialTemplate,
	tx *Transaction,
) (*CredentialOfferResponse, error) {
	targetFormat, err := verifiable.MapFormatToOIDCFormat(tx.CredentialFormat)
	if err != nil {
		return nil, err
	}

	issuerURL, _ := url.JoinPath(s.issuerVCSPublicHost, "issuer", tx.ProfileID)

	resp := &CredentialOfferResponse{
		CredentialIssuer: issuerURL,
		Credentials: []CredentialOffer{
			{
				Format: targetFormat,
				Types: []string{
					"VerifiableCredential",
					template.Type,
				},
			},
		},
		Grants: CredentialOfferGrant{},
	}

	if tx.IsPreAuthFlow {
		resp.Grants.PreAuthorizationGrant = &PreAuthorizationGrant{
			PreAuthorizedCode: tx.PreAuthCode,
			UserPinRequired:   req.UserPinRequired,
		}
	} else {
		resp.Grants.AuthorizationCode = &AuthorizationCodeGrant{
			IssuerState: req.OpState,
		}
	}

	return resp, nil
}

func (s *Service) buildInitiateIssuanceURL(
	ctx context.Context,
	req *InitiateIssuanceRequest,
	offerURL string,
	offer *CredentialOfferResponse,
) (string, error) {
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
		initiateIssuanceURL = "openid-vc://"
	}

	q := url.Values{}
	if offerURL != "" {
		q.Set("credential_offer_uri", offerURL)
	} else {
		b, err := json.Marshal(offer)
		if err != nil {
			return "", err
		}
		q.Set("credential_offer", string(b))
	}

	return initiateIssuanceURL + "?" + q.Encode(), nil
}
