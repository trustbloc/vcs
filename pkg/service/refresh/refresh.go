/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh

import (
	"context"
	"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/claims"
	"github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

type Config struct {
	VcsAPIURL              string
	TxStore                transactionStore1
	ClaimsStore            claimDataStore
	DataProtector          dataProtector
	PresentationVerifier   presentationVerifier
	CredentialIssuer       credentialIssuer
	IssueCredentialService issuecredential.ServiceInterface
}

type Service struct {
	cfg *Config
}

func NewRefreshService(cfg *Config) *Service {
	return &Service{
		cfg: cfg,
	}
}

func (s *Service) GetRefreshedCredential(ctx context.Context, presentation *verifiable.Presentation, issuer profile.Issuer) (*verifiable.Credential, error) {
	verifyResult, _, err := s.cfg.PresentationVerifier.VerifyPresentation(ctx, presentation, nil, &profile.Verifier{
		Checks: &profile.VerificationChecks{
			Presentation: &profile.PresentationChecks{
				Proof: true,
			},
			Credential: profile.CredentialChecks{
				Proof:            true,
				CredentialExpiry: true,
				Status:           true,
				LinkedDomain:     false,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if len(verifyResult) > 0 {
		return nil, fmt.Errorf("presentation verification failed. %s", spew.Sdump(verifyResult))
	}

	if len(presentation.Credentials()) == 0 {
		return nil, errors.New("no credentials in presentation")
	}
	cred := presentation.Credentials()[0]

	allTypes := cred.Contents().Types
	if len(allTypes) == 0 {
		return nil, errors.New("no types in credential")
	}

	lastType := allTypes[len(cred.Contents().Types)-1]

	var template *profile.CredentialTemplate
	for _, t := range issuer.CredentialTemplates {
		if t.Type == lastType {
			template = t
			break
		}
	}

	if template == nil {
		return nil, fmt.Errorf("no credential template found for credential type %v", lastType)
	}

	var config *profile.CredentialsConfigurationSupported
	var configID string

	for k, v := range issuer.CredentialMetaData.CredentialsConfigurationSupported {
		if v.CredentialDefinition == nil {
			continue
		}

		if lo.Contains(v.CredentialDefinition.Type, lastType) {
			config = v
			configID = k
			break
		}
	}

	if config == nil {
		return nil, fmt.Errorf("no credential configuration found for credential type %v", lastType)
	}

	tx, err := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(cred.Contents().ID, issuer.ID))
	if err != nil {
		return nil, err
	}

	tempClaimData, err := s.cfg.ClaimsStore.GetAndDelete(ctx, tx.CredentialConfiguration[0].ClaimDataID)
	if err != nil {
		return nil, err
	}

	decryptedClaims, decryptErr := claims.DecryptClaims(ctx, tempClaimData, s.cfg.DataProtector)
	if decryptErr != nil {
		return nil, fmt.Errorf("decrypt claims: %w", decryptErr)
	}

	subj := cred.Contents().Subject
	if len(subj) == 0 {
		return nil, errors.New("no subject in credential")
	}

	credConfig := tx.CredentialConfiguration[0]

	credConfig.CredentialConfigurationID = configID
	credConfig.OIDCCredentialFormat = config.Format
	credConfig.CredentialTemplate = template

	updatedCred, err := s.cfg.CredentialIssuer.PrepareCredential(ctx, &issuecredential.PrepareCredentialsRequest{
		TxID:                    string(tx.ID),
		ClaimData:               decryptedClaims,
		IssuerDID:               tx.DID,
		SubjectDID:              subj[0].ID,
		CredentialConfiguration: credConfig,
		IssuerID:                issuer.ID,
		IssuerVersion:           issuer.Version,
	})
	if err != nil {
		return nil, errors.Join(errors.New("failed to prepare credential"), err)
	}

	updatedCred, err = s.cfg.IssueCredentialService.IssueCredential(ctx, updatedCred, &issuer,
		issuecredential.WithTransactionID(string(tx.ID)),
		issuecredential.WithSkipIDPrefix(),
	)

	return updatedCred, err
}

func (s *Service) RequestRefreshStatus(
	ctx context.Context,
	credentialID string,
	issuer profile.Issuer,
) (*oidc4ci.GetRefreshStateResponse, error) {
	tx, _ := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(credentialID, issuer.ID))
	if tx == nil {
		return nil, nil
	}

	purpose := "The verifier needs to see your existing credentials to verify your identity"

	return &oidc4ci.GetRefreshStateResponse{
		RefreshServiceType: oidc4ci.RefreshServiceType{
			Type: "VerifiableCredentialRefreshService2021",
		},
		VerifiablePresentationRequest: oidc4ci.VerifiablePresentationRequest{
			Query: presexch.PresentationDefinition{
				ID:                     "Query",
				Name:                   "We need to see your existing credentials",
				Purpose:                purpose,
				Frame:                  nil,
				SubmissionRequirements: nil,
				InputDescriptors: []*presexch.InputDescriptor{
					{
						ID:      "DescriptorID",
						Name:    "We need to see your existing credentials",
						Purpose: purpose,
						Constraints: &presexch.Constraints{
							Fields: []*presexch.Field{
								{
									Path: []string{
										"$.id",
									},
									ID:      "cred_id",
									Purpose: purpose,
									Filter: &presexch.Filter{
										Type:  lo.ToPtr("string"),
										Const: credentialID,
									},
									Optional: false,
								},
							},
						},
					},
				},
			},
		},
		Challenge: uuid.NewString(),
		Domain:    s.cfg.VcsAPIURL,
	}, nil
}

func (s *Service) CreateRefreshState(
	ctx context.Context,
	req *oidc4ci.CreateRefreshStateRequest,
) (string, error) {
	encrypted, err := claims.EncryptClaims(ctx, req.Claims, s.cfg.DataProtector)
	if err != nil {
		return "", err
	}

	ttl := req.Issuer.DataConfig.OIDC4CITransactionDataTTL

	claimData, err := s.cfg.ClaimsStore.Create(ctx, ttl, &issuecredential.ClaimData{
		EncryptedData: encrypted.EncryptedData,
	})
	if err != nil {
		return "", errors.Join(errors.New("failed to create claim data"), err)
	}

	opState := s.getOpState(req.CredentialID, req.Issuer.ID)

	tx, err := s.cfg.TxStore.Create(ctx, ttl, &issuecredential.TransactionData{
		ProfileID:      req.Issuer.ID,
		ProfileVersion: req.Issuer.Version,
		IsPreAuthFlow:  true,
		OrgID:          req.Issuer.OrganizationID,
		OpState:        opState,
		WebHookURL:     req.Issuer.WebHook,
		CredentialConfiguration: []*issuecredential.TxCredentialConfiguration{
			{
				ClaimDataType:         issuecredential.ClaimDataTypeClaims,
				ClaimDataID:           claimData,
				CredentialName:        lo.FromPtr(req.CredentialName),
				CredentialDescription: lo.FromPtr(req.CredentialDescription),
			},
		},
	})
	if err != nil {
		return "", errors.Join(errors.New("failed to create transaction"), err)
	}

	return string(tx.ID), nil
}

func (s *Service) getOpState(refreshID string, issuerID string) string {
	return fmt.Sprintf("%s-%s", issuerID, refreshID)
}
