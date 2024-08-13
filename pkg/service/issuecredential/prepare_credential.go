/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
)

const (
	defaultCtx = "https://www.w3.org/2018/credentials/v1"
)

type PrepareCredentialService struct {
	cfg *PrepareCredentialServiceConfig
}

type PrepareCredentialServiceConfig struct {
	VcsAPIURL string
	Composer  composer
}

func NewPrepareCredentialService(
	cfg *PrepareCredentialServiceConfig,
) *PrepareCredentialService {
	return &PrepareCredentialService{
		cfg: cfg,
	}
}

func (s *PrepareCredentialService) PrepareCredential(
	ctx context.Context,
	req *PrepareCredentialsRequest,
) (*verifiable.Credential, error) {
	if req.CredentialConfiguration == nil {
		return nil, fmt.Errorf("missing credential configuration")
	}

	var finalCred *verifiable.Credential
	var err error

	switch req.CredentialConfiguration.ClaimDataType {
	case ClaimDataTypeClaims:
		finalCred, err = s.prepareCredentialFromClaims(
			ctx,
			req,
		)
	case ClaimDataTypeVC:
		finalCred, err = s.prepareCredentialFromCompose(
			ctx,
			req,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("prepare credential: %w", err)
	}

	if finalCred == nil {
		return nil, fmt.Errorf("prepare credential: final credential is nil")
	}

	if req.RefreshServiceEnabled {
		finalCred = finalCred.WithModifiedRefreshService(s.CreateRefreshService(ctx, finalCred, req))
	}

	return finalCred, err
}

func (s *PrepareCredentialService) prepareCredentialFromClaims(
	_ context.Context,
	req *PrepareCredentialsRequest,
) (*verifiable.Credential, error) {
	contexts := req.CredentialConfiguration.CredentialTemplate.Contexts
	if len(contexts) == 0 {
		contexts = []string{defaultCtx}
	}

	// prepare credential for signing
	vcc := verifiable.CredentialContents{
		Context: contexts,
		ID:      uuid.New().URN(),
		Types:   []string{"VerifiableCredential", req.CredentialConfiguration.CredentialTemplate.Type},
		Issuer:  &verifiable.Issuer{ID: req.IssuerDID},
		Issued:  util.NewTime(time.Now()),
	}

	customFields := map[string]interface{}{}

	if req.CredentialConfiguration.CredentialDescription != "" {
		customFields["description"] = req.CredentialConfiguration.CredentialDescription
	}
	if req.CredentialConfiguration.CredentialName != "" {
		customFields["name"] = req.CredentialConfiguration.CredentialName
	}

	if req.CredentialConfiguration.CredentialExpiresAt != nil {
		vcc.Expired = util.NewTime(*req.CredentialConfiguration.CredentialExpiresAt)
	}

	if req.ClaimData != nil {
		vcc.Subject = []verifiable.Subject{{
			ID:           req.SubjectDID,
			CustomFields: req.ClaimData,
		}}
	} else {
		vcc.Subject = []verifiable.Subject{{ID: req.SubjectDID}}
	}

	return verifiable.CreateCredential(vcc, customFields)
}

func (s *PrepareCredentialService) prepareCredentialFromCompose(
	ctx context.Context,
	req *PrepareCredentialsRequest,
) (*verifiable.Credential, error) {
	cred, err := verifiable.ParseCredentialJSON(req.ClaimData,
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential json: %w", err)
	}

	return s.cfg.Composer.Compose(ctx, cred, req)
}

func (s *PrepareCredentialService) CreateRefreshService(
	_ context.Context,
	cred *verifiable.Credential,
	req *PrepareCredentialsRequest,
) *verifiable.TypedID {
	return &verifiable.TypedID{
		Type: "VerifiableCredentialRefreshService2021",
		ID:   s.getRefreshServiceURL(cred.Contents().ID, req.IssuerID, req.IssuerVersion),
	}
}

func (s *PrepareCredentialService) getRefreshServiceURL(
	credentialID string,
	issuerID string,
	issuerVersion string,
) string {
	return fmt.Sprintf("%s/refresh/%s/%s?credentialID=%s",
		s.cfg.VcsAPIURL,
		issuerID,
		issuerVersion,
		url.QueryEscape(credentialID),
	)
}
