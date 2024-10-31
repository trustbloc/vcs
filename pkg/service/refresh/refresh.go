/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/claims"
	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

var logger = log.New("refresh-service")

const (
	ServiceComponent = "RefreshService"
)

type Config struct {
	VcsAPIURL              string
	TxStore                transactionStore1
	ClaimsStore            claimDataStore
	DataProtector          dataProtector
	PresentationVerifier   presentationVerifier
	CredentialIssuer       credentialIssuer
	IssueCredentialService IssueCredService
	EventPublisher         EventPublisher
	EventTopic             string
}

type Service struct {
	cfg *Config
}

func NewRefreshService(cfg *Config) *Service {
	return &Service{
		cfg: cfg,
	}
}

func (s *Service) getEvent(
	eventType spi.EventType,
	payloadData *Event,
	txID string,
) (*spi.Event, error) {
	payload, err := json.Marshal(payloadData)
	if err != nil {
		return nil, err
	}

	event := spi.NewEventWithPayload(uuid.NewString(), "RefreshService", eventType, payload)
	event.TransactionID = txID

	return event, nil
}

func (s *Service) publishEvent(
	ctx context.Context,
	eventType spi.EventType,
	payloadData *Event,
	txID string,
) error {
	event, err := s.getEvent(eventType, payloadData, txID)
	if err != nil {
		return err
	}

	return s.cfg.EventPublisher.Publish(ctx, s.cfg.EventTopic, event)
}

func (s *Service) tryPublish(
	ctx context.Context,
	eventType spi.EventType,
	payloadData *Event,
	txID string,
	errSource error,
) {
	if errSource != nil {
		payloadData.Error = errSource.Error()
		payloadData.ErrorComponent = ServiceComponent
	}

	if err := s.publishEvent(ctx, eventType, payloadData, txID); err != nil {
		logger.Errorc(ctx, fmt.Sprintf("failed to publish event: %s", err),
			logfields.WithProfileID(payloadData.ProfileID),
			logfields.WithTransactionID(txID),
		)
	}
}

//nolint:funlen
func (s *Service) GetRefreshedCredential(
	ctx context.Context,
	presentation *verifiable.Presentation,
	issuer profile.Issuer,
) (*GetRefreshedCredentialResponse, error) {
	resultEvent := &Event{
		WebHook:        issuer.WebHook,
		ProfileID:      issuer.ID,
		ProfileVersion: issuer.Version,
		OrgID:          issuer.OrganizationID,
	}

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
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	if verifyResult.HasErrors() {
		err = fmt.Errorf("presentation verification failed. %s", spew.Sdump(verifyResult))
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	if len(presentation.Credentials()) == 0 {
		err = errors.New("no credentials in presentation")
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}
	cred := presentation.Credentials()[0]

	template, err := s.findCredentialTemplate(cred.Contents().Types, issuer)
	if err != nil {
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	config, configID := s.findCredConfigSupported(issuer, template.Type)
	if config == nil {
		err = fmt.Errorf("no credential configuration found for credential type %v", template.Type)
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	tx, err := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(cred.Contents().ID, issuer.ID))
	if err != nil {
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	tempClaimData, err := s.cfg.ClaimsStore.GetAndDelete(ctx, tx.CredentialConfiguration[0].ClaimDataID)
	if err != nil {
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	decryptedClaims, decryptErr := claims.DecryptClaims(ctx, tempClaimData, s.cfg.DataProtector)
	if decryptErr != nil {
		decryptErr = fmt.Errorf("decrypt claims: %w", decryptErr)
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", decryptErr)

		return nil, decryptErr
	}

	subj := cred.Contents().Subject
	if len(subj) == 0 {
		err = errors.New("no subject in credential")
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	credConfig := tx.CredentialConfiguration[0]

	credConfig.CredentialConfigurationID = configID
	credConfig.OIDCCredentialFormat = config.Format
	credConfig.CredentialTemplate = template

	if template.CredentialDefaultExpirationDuration != nil {
		credConfig.CredentialExpiresAt = lo.ToPtr(time.Now().UTC().Add(*template.CredentialDefaultExpirationDuration))
	} else {
		credConfig.CredentialExpiresAt = lo.ToPtr(time.Now().UTC().Add(365 * 24 * time.Hour))
	}

	refreshServiceEnabled := false
	if issuer.VCConfig != nil {
		refreshServiceEnabled = true
	}

	updatedCred, err := s.cfg.CredentialIssuer.PrepareCredential(ctx, &issuecredential.PrepareCredentialsRequest{
		TxID:                    string(tx.ID),
		ClaimData:               decryptedClaims,
		IssuerDID:               tx.DID,
		SubjectDID:              subj[0].ID,
		CredentialConfiguration: credConfig,
		IssuerID:                issuer.ID,
		IssuerVersion:           issuer.Version,
		RefreshServiceEnabled:   refreshServiceEnabled,
	})
	if err != nil {
		err = errors.Join(errors.New("failed to prepare credential"), err)
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, "", err)

		return nil, err
	}

	updatedCred, err = s.cfg.IssueCredentialService.IssueCredential(ctx, updatedCred, &issuer,
		issuecredential.WithTransactionID(string(tx.ID)),
		issuecredential.WithSkipIDPrefix(),
	)

	if err != nil {
		s.tryPublish(ctx, spi.CredentialRefreshFailed, resultEvent, string(tx.ID), err)
		return nil, err
	}

	issuerURL, _ := url.JoinPath(s.cfg.VcsAPIURL, "oidc/idp", tx.ProfileID, tx.ProfileVersion)

	credentialResponse := &GetRefreshedCredentialResponse{
		Credential: updatedCred,
		IssuerURL:  issuerURL,
	}

	s.tryPublish(ctx, spi.CredentialRefreshSuccessful, resultEvent, string(tx.ID), nil)

	return credentialResponse, nil
}

func (s *Service) findCredentialTemplate(
	allTypes []string,
	issuer profile.Issuer,
) (*profile.CredentialTemplate, error) {
	if len(allTypes) == 0 {
		return nil, errors.New("no types in credential")
	}

	lastType := allTypes[len(allTypes)-1]

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

	return template, nil
}

func (s *Service) findCredConfigSupported(
	issuer profile.Issuer,
	lastType string,
) (*profile.CredentialsConfigurationSupported, string) {
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

	return config, configID
}

func (s *Service) RequestRefreshStatus(
	ctx context.Context,
	credentialID string,
	issuer profile.Issuer,
) (*GetRefreshStateResponse, error) {
	tx, _ := s.cfg.TxStore.FindByOpState(ctx, s.getOpState(credentialID, issuer.ID))
	if tx == nil {
		return nil, nil //nolint: nilnil
	}

	purpose := "The verifier needs to see your existing credentials to verify your identity"

	s.tryPublish(ctx, spi.CredentialRefreshInitiated, &Event{
		WebHook:        issuer.WebHook,
		ProfileID:      issuer.ID,
		ProfileVersion: issuer.Version,
		OrgID:          issuer.OrganizationID,
	}, string(tx.ID), nil)

	return &GetRefreshStateResponse{
		RefreshServiceType: ServiceType{
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

func (s *Service) CreateRefreshState(
	ctx context.Context,
	req *CreateRefreshStateRequest,
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

	refreshServiceEnabled := false
	if req.Issuer.VCConfig != nil {
		refreshServiceEnabled = req.Issuer.VCConfig.RefreshServiceEnabled
	}

	tx, err := s.cfg.TxStore.ForceCreate(ctx, ttl, &issuecredential.TransactionData{
		ProfileID:             req.Issuer.ID,
		ProfileVersion:        req.Issuer.Version,
		IsPreAuthFlow:         true,
		OrgID:                 req.Issuer.OrganizationID,
		OpState:               opState,
		WebHookURL:            req.Issuer.WebHook,
		RefreshServiceEnabled: refreshServiceEnabled,
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
