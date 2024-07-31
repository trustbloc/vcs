package oidc4ci

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/pkg/profile"
)

type RefreshConfig struct {
	VcsApiURL            string
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

func (s *RefreshService) CreateRefreshService(
	_ context.Context,
	issuer profile.Issuer,
	id *string,
) *verifiable.RefreshService {
	if lo.FromPtr(id) == "" {
		id = lo.ToPtr(uuid.NewString())
	}

	return &verifiable.RefreshService{
		TypedID: verifiable.TypedID{
			Type: "VerifiableCredentialRefreshService2021",
			CustomFields: verifiable.CustomFields{
				"validFrom": time.Now().UTC().Format(time.RFC3339),
			},
		},
		Url: s.getUrl(*id, issuer.ID),
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

	//cred.Contents().Types

	return nil
}

func (s *RefreshService) GetRefreshState(
	ctx context.Context,
	refreshID string,
	issuer profile.Issuer,
) (*GetRefreshStateResponse, error) {
	tx, _ := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(refreshID, issuer.ID))
	if tx == nil {
		return nil, nil
	}

	targetPath := s.getUrl(refreshID, issuer.ID)
	purpose := "The verifier needs to see your existing credentials to verify your identity"

	return &GetRefreshStateResponse{
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
										"$.refreshService.url",
									},
									ID:      "refresh_id",
									Purpose: purpose,
									Filter: &presexch.Filter{
										Type:  lo.ToPtr("string"),
										Const: targetPath,
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
		Domain:    s.cfg.VcsApiURL,
	}, nil
}

func (s *RefreshService) CreateRefreshClaims(
	ctx context.Context,
	req *CreateRefreshClaimsRequest,
) error {
	encrypted, err := encryptClaims(ctx, req.Claims, s.cfg.DataProtector)
	if err != nil {
		return err
	}

	ttl := req.Issuer.DataConfig.OIDC4CITransactionDataTTL

	claimData, err := s.cfg.ClaimsStore.Create(ctx, ttl, &ClaimData{
		EncryptedData: encrypted.EncryptedData,
	})
	if err != nil {
		return errors.Join(errors.New("failed to create claim data"), err)
	}

	_, err = s.cfg.TxStore.Create(ctx, ttl, &TransactionData{
		ProfileID:      req.Issuer.ID,
		ProfileVersion: req.Issuer.Version,
		IsPreAuthFlow:  true,
		OrgID:          req.Issuer.OrganizationID,
		OpState:        s.getOpState(req.RefreshID, req.Issuer.ID),
		WebHookURL:     req.Issuer.WebHook,
		CredentialConfiguration: []*TxCredentialConfiguration{
			{
				CredentialTemplate:        nil,
				OIDCCredentialFormat:      "",
				ClaimDataType:             ClaimDataTypeClaims,
				ClaimDataID:               claimData,
				CredentialName:            req.CredentialName,
				CredentialDescription:     req.CredentialDescription,
				CredentialConfigurationID: "",
			},
		},
	})

	return err
}

func (s *RefreshService) getUrl(refreshID string, issuerID string) string {
	return fmt.Sprintf("%s/refresh/%s/%s", s.cfg.VcsApiURL, issuerID, refreshID)
}

func (s *RefreshService) getOpState(refreshId string, issuerID string) string {
	return fmt.Sprintf("%s-%s", issuerID, refreshId)
}
