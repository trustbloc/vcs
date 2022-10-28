/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination oidc4vc_service_mocks_test.go -self_package mocks -package oidc4vc_test -source=oidc4vc_service.go -mock_names transactionStore=MockTransactionStore,wellKnownService=MockWellKnownService

package oidc4vc

import (
	"context"
	"fmt"

	"github.com/trustbloc/vcs/internal/pkg/log"
	"github.com/trustbloc/vcs/pkg/storage"
)

const (
	defaultGrantType    = "authorization_code"
	defaultResponseType = "token"
	defaultScope        = "openid"
)

var logger = log.New("oidc4vc")

type transactionStore interface {
	Create(
		ctx context.Context,
		data *TransactionData,
		params ...func(insertOptions *storage.InsertOptions),
	) (*Transaction, error)

	FindByOpState(
		ctx context.Context,
		opState string,
	) (*Transaction, error)

	Update(
		ctx context.Context,
		tx *Transaction,
	) error
}

type wellKnownService interface {
	GetOIDCConfiguration(ctx context.Context, url string) (*OIDCConfiguration, error)
}

// Config holds configuration options and dependencies for Service.
type Config struct {
	TransactionStore    transactionStore
	WellKnownService    wellKnownService
	IssuerVCSPublicHost string
}

// Service implements VCS credential interaction API for OIDC4VC issuance.
type Service struct {
	store               transactionStore
	wellKnownService    wellKnownService
	issuerVCSPublicHost string
}

// NewService returns a new Service instance.
func NewService(config *Config) (*Service, error) {
	return &Service{
		store:               config.TransactionStore,
		wellKnownService:    config.WellKnownService,
		issuerVCSPublicHost: config.IssuerVCSPublicHost,
	}, nil
}

func (s *Service) PrepareClaimDataAuthorizationRequest(
	ctx context.Context,
	req *PrepareClaimDataAuthorizationRequest,
) (*PrepareClaimDataAuthorizationResponse, error) {
	tx, err := s.store.FindByOpState(ctx, req.OpState)
	if err != nil {
		return nil, err
	}

	return &PrepareClaimDataAuthorizationResponse{
		AuthorizationParameters: &IssuerAuthorizationRequestParameters{
			ClientID:     tx.ClientID,
			RedirectURI:  req.RedirectURI,
			ResponseType: req.ResponseType,
			Scope:        req.Scope,
		},
		AuthorizationEndpoint:              tx.AuthorizationEndpoint,
		PushedAuthorizationRequestEndpoint: tx.PushedAuthorizationRequestEndpoint,
		TxID:                               tx.ID,
	}, nil
}

func (s *Service) HandlePAR(ctx context.Context, opState string, ad *AuthorizationDetails) (TxID, error) {
	tx, err := s.store.FindByOpState(ctx, opState)
	if err != nil {
		return "", fmt.Errorf("get transaction by opstate: %w", err)
	}

	if ad.CredentialType != tx.AuthorizationDetails.CredentialType {
		return "", fmt.Errorf("authorization details credential type mismatch")
	}

	if ad.Format != tx.AuthorizationDetails.Format {
		return "", fmt.Errorf("authorization details format mismatch")
	}

	return tx.ID, nil
}
