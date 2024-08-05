package oidc4ci

import (
	"context"
	"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/profile"
)

type RefreshConfig struct {
	VcsAPIURL            string
	TxStore              transactionStore
	ClaimsStore          claimDataStore
	DataProtector        dataProtector
	PresentationVerifier presentationVerifier
	CredentialIssuer     credentialIssuer
}

type RefreshService struct {
	cfg *RefreshConfig
}

func NewRefreshService(cfg *RefreshConfig) *RefreshService {
	return &RefreshService{
		cfg: cfg,
	}
}

func (s *RefreshService) RefreshCredential(
	ctx context.Context,
	presentation *verifiable.Presentation,
	issuer profile.Issuer,
) error {
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
		return err
	}

	if len(verifyResult) > 0 {
		return fmt.Errorf("presentation verification failed. %s", spew.Sdump(verifyResult))
	}

	if len(presentation.Credentials()) == 0 {
		return errors.New("no credentials in presentation")
	}
	cred := presentation.Credentials()[0]

	allTypes := cred.Contents().Types
	if len(allTypes) == 0 {
		return errors.New("no types in credential")
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
		return fmt.Errorf("no credential template found for credential type %v", lastType)
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
		return fmt.Errorf("no credential configuration found for credential type %v", lastType)
	}

	tx, err := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(cred.Contents().ID, issuer.ID))
	if err != nil {
		return err
	}

	tempClaimData, err := s.cfg.ClaimsStore.GetAndDelete(ctx, tx.CredentialConfiguration[0].ClaimDataID)
	if err != nil {
		return err
	}

	decryptedClaims, decryptErr := decryptClaims(ctx, tempClaimData, s.cfg.DataProtector)
	if decryptErr != nil {
		return fmt.Errorf("decrypt claims: %w", decryptErr)
	}

	subj := cred.Contents().Subject
	if len(subj) == 0 {
		return errors.New("no subject in credential")
	}

	credConfig := tx.CredentialConfiguration[0]

	credConfig.CredentialConfigurationID = configID
	credConfig.OIDCCredentialFormat = config.Format
	credConfig.CredentialTemplate = template

	updatedCred, err := s.cfg.CredentialIssuer.PrepareCredential(ctx, &PrepareCredentialsRequest{
		TxID:                    string(tx.ID),
		ClaimData:               decryptedClaims,
		IssuerDID:               tx.DID,
		SubjectDID:              subj[0].ID,
		CredentialConfiguration: credConfig,
		IssuerID:                issuer.ID,
		IssuerVersion:           issuer.Version,
	})
	if err != nil {
		return errors.Join(errors.New("failed to prepare credential"), err)
	}

	fmt.Println(updatedCred)

	return nil
}

func (s *RefreshService) RequestRefreshStatus(
	ctx context.Context,
	credentialID string,
	issuer profile.Issuer,
) (*GetRefreshStateResponse, error) {
	tx, _ := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(credentialID, issuer.ID))
	if tx == nil {
		return nil, nil
	}

	purpose := "The verifier needs to see your existing credentials to verify your identity"

	return &GetRefreshStateResponse{
		RefreshServiceType: RefreshServiceType{
			Type: "VerifiableCredentialRefreshService2021",
		},
		VerifiablePresentationRequest: VerifiablePresentationRequest{
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

func (s *RefreshService) CreateRefreshState(
	ctx context.Context,
	req *CreateRefreshStateRequest,
) (string, error) {
	encrypted, err := encryptClaims(ctx, req.Claims, s.cfg.DataProtector)
	if err != nil {
		return "", err
	}

	ttl := req.Issuer.DataConfig.OIDC4CITransactionDataTTL

	claimData, err := s.cfg.ClaimsStore.Create(ctx, ttl, &ClaimData{
		EncryptedData: encrypted.EncryptedData,
	})
	if err != nil {
		return "", errors.Join(errors.New("failed to create claim data"), err)
	}

	opState := s.getOpState(req.CredentialID, req.Issuer.ID)

	tx, err := s.cfg.TxStore.Create(ctx, ttl, &TransactionData{
		ProfileID:      req.Issuer.ID,
		ProfileVersion: req.Issuer.Version,
		IsPreAuthFlow:  true,
		OrgID:          req.Issuer.OrganizationID,
		OpState:        opState,
		WebHookURL:     req.Issuer.WebHook,
		CredentialConfiguration: []*TxCredentialConfiguration{
			{
				ClaimDataType:         ClaimDataTypeClaims,
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

func (s *RefreshService) getOpState(refreshID string, issuerID string) string {
	return fmt.Sprintf("%s-%s", issuerID, refreshID)
}
