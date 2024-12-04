/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks_test.go -self_package mocks -package eventhandler -source=eventhandler_service.go -mock_names CSLService=MockCSLService

package eventhandler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/doc/vc/statustype"
	"github.com/trustbloc/vcs/pkg/event/spi"
	"github.com/trustbloc/vcs/pkg/service/credentialstatus"
)

var logger = log.New("credentialstatus-eventhandler")

const jsonStatusListType = "type"

type CSLService interface {
	SignCSL(profileID, profileVersion string, csl *verifiable.Credential) ([]byte, error)
	GetCSLVCWrapper(ctx context.Context, cslURL string) (*credentialstatus.CSLVCWrapper, error)
	UpsertCSLVCWrapper(ctx context.Context, cslURL string, wrapper *credentialstatus.CSLVCWrapper) error
}

type Config struct {
	CSLService CSLService
}

type Service struct {
	cslService CSLService
}

func New(conf *Config) *Service {
	return &Service{
		cslService: conf.CSLService,
	}
}

// HandleEvent is responsible for the handling of spi.CredentialStatusStatusUpdated events.
func (s *Service) HandleEvent(ctx context.Context, event *spi.Event) error { //nolint:gocognit
	logger.Infoc(ctx, "Received event", logfields.WithEvent(event))

	if event.Type != spi.CredentialStatusStatusUpdated {
		return nil
	}

	payload := credentialstatus.UpdateCredentialStatusEventPayload{}

	doc, ok := event.Data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid event data")
	}

	jsonData, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(jsonData, &payload); err != nil {
		return err
	}

	return s.handleEventPayload(ctx, payload)
}

func (s *Service) handleEventPayload(
	ctx context.Context, payload credentialstatus.UpdateCredentialStatusEventPayload) error {
	clsWrapper, err := s.cslService.GetCSLVCWrapper(ctx, payload.CSLURL)
	if err != nil {
		return fmt.Errorf("get CSL VC wrapper failed: %w", err)
	}

	cs := clsWrapper.VC.Contents().Subject

	statusType, err := getStringValue(jsonStatusListType, cs[0].CustomFields)
	if err != nil {
		return fmt.Errorf("failed to get status list type: %w", err)
	}

	processor, err := statustype.GetVCStatusProcessor(vc.StatusType(statusType))
	if err != nil {
		return fmt.Errorf("failed to get VCStatusProcessor: %w", err)
	}

	clsWrapper.VC, err = processor.UpdateStatus(clsWrapper.VC, payload.Status, payload.Index)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	signedCredentialBytes, err := s.cslService.SignCSL(payload.ProfileID, payload.ProfileVersion, clsWrapper.VC)
	if err != nil {
		return fmt.Errorf("failed to sign CSL: %w", err)
	}

	vcWrapper := &credentialstatus.CSLVCWrapper{
		VCByte: signedCredentialBytes,
	}

	if err = s.cslService.UpsertCSLVCWrapper(ctx, payload.CSLURL, vcWrapper); err != nil {
		return fmt.Errorf("save CSL failed: %w", err)
	}

	return nil
}

func getStringValue(key string, vMap map[string]interface{}) (string, error) {
	if val, ok := vMap[key]; ok {
		if s, ok := val.(string); ok {
			return s, nil
		}

		return "", fmt.Errorf("invalid '%s' type", key)
	}

	return "", nil
}
