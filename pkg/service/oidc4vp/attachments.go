/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination attachments_mocks_test.go -self_package mocks -package oidc4vp_test -source=attachments.go -mock_names httpClient=MockHttpClient

package oidc4vp

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/util/maphelpers"
	"github.com/trustbloc/vc-go/verifiable"
)

const (
	AttachmentTypeRemote       = "RemoteAttachment"
	AttachmentTypeEmbedded     = "EmbeddedAttachment"
	AttachmentEvidence         = "AttachmentEvidence"
	AttachmentDataField        = "uri"
	AttachmentIDField          = "id"
	AttachmentHashField        = "hash"
	AttachmentHashAlgoField    = "hash-alg"
	AttachmentErrorField       = "error"
	AttachmentDescriptionField = "description"
)

// nolint:gochecknoglobals
var knownAttachmentTypes = []string{
	AttachmentTypeRemote,
	AttachmentTypeEmbedded,
	AttachmentEvidence,
}

type AttachmentService struct {
	httpClient httpClient
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewAttachmentService(
	httpClient httpClient,
) *AttachmentService {
	return &AttachmentService{
		httpClient: httpClient,
	}
}

func (s *AttachmentService) getAttachmentByTypes(
	_ context.Context,
	subjects []verifiable.Subject,
	attachmentTypes []string,
) []*attachmentData {
	var allAttachments []*attachmentData

	for _, subject := range subjects {
		allAttachments = append(allAttachments,
			s.findAttachments(subject.CustomFields, attachmentTypes)...,
		)
	}

	return allAttachments
}

func (s *AttachmentService) handleEvidenceAttachment(
	_ context.Context,
	attachment map[string]interface{},
	idTokenAttachments map[string]string,
) error {
	if len(idTokenAttachments) == 0 {
		return errors.New("id token attachments are empty")
	}

	idAttachment, ok := attachment[AttachmentIDField].(string)
	if !ok {
		return errors.New("attachment id field is required")
	}

	idTokenAttachment, ok := idTokenAttachments[idAttachment]
	if !ok {
		return fmt.Errorf("id token attachment not found for id: %s", idAttachment)
	}

	bodySegments := strings.Split(idTokenAttachment, ",") // skip data:%s;base64,%s
	rawBody, err := base64.StdEncoding.DecodeString(bodySegments[len(bodySegments)-1])
	if err != nil {
		return fmt.Errorf("failed to decode base64 body id token attachment: %w", err)
	}

	if err = s.validateHash(attachment, rawBody); err != nil {
		return fmt.Errorf("failed to validate hash for attachment id %s: %w", idAttachment, err)
	}

	attachment[AttachmentDataField] = idTokenAttachment

	return nil
}

func (s *AttachmentService) GetAttachments(
	ctx context.Context,
	subjects []verifiable.Subject,
	idTokenAttachments map[string]string,
) ([]*Attachment, error) {
	allAttachments := s.getAttachmentByTypes(ctx, subjects, knownAttachmentTypes)

	if len(allAttachments) == 0 {
		return nil, nil
	}

	var resultAttachments []map[string]interface{}

	var wg sync.WaitGroup
	for _, attachment := range allAttachments {
		cloned := maphelpers.CopyMap(attachment.Claim)
		attachment.Claim = cloned

		resultAttachments = append(resultAttachments, attachment.Claim)

		switch attachment.Type {
		case AttachmentEvidence:
			if err := s.handleEvidenceAttachment(ctx, cloned, idTokenAttachments); err != nil {
				cloned[AttachmentErrorField] = fmt.Sprintf("failed to handle evidence attachment: %s", err)
			}
		case AttachmentTypeRemote:
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := s.handleRemoteAttachment(ctx, cloned)
				if err != nil {
					cloned[AttachmentErrorField] = fmt.Sprintf("failed to handle remote attachment: %s", err)
				}
			}()
		default:
			continue
		}
	}
	wg.Wait()

	var final []*Attachment
	for _, attachment := range resultAttachments {
		att := &Attachment{
			ID: fmt.Sprint(attachment[AttachmentIDField]),
		}

		if v, ok := attachment[AttachmentDataField]; ok {
			att.DataURI = fmt.Sprint(v)
		}
		if v, ok := attachment[AttachmentDescriptionField]; ok {
			att.Description = fmt.Sprint(v)
		}
		if v, ok := attachment[AttachmentErrorField]; ok {
			att.Error = fmt.Sprint(v)
		}

		final = append(final, att)
	}

	return final, nil
}

func (s *AttachmentService) validateHash(
	attachment map[string]interface{},
	body []byte,
) error {
	hash, ok := attachment[AttachmentHashField].(string)
	if !ok {
		return fmt.Errorf("attachment %s field is required", AttachmentHashField)
	}

	hashAlgo, ok := attachment[AttachmentHashAlgoField].(string)
	if !ok {
		return fmt.Errorf("attachment %s field is required", AttachmentHashAlgoField)
	}

	switch hashAlgo {
	case "SHA-256":
		if err := s.validateSHA256Hash(hash, body); err != nil {
			return fmt.Errorf("failed to validate %v hash: %w", hashAlgo, err)
		}
	case "SHA-384":
		if err := s.validateSHA384Hash(hash, body); err != nil {
			return fmt.Errorf("failed to validate %v hash: %w", hashAlgo, err)
		}
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", hashAlgo)
	}

	return nil
}

func (s *AttachmentService) validateSHA256Hash(hash string, data []byte) error {
	computedHash := sha256.Sum256(data)
	computedHashHex := hex.EncodeToString(computedHash[:])

	if computedHashHex != hash {
		return errors.New("hash mismatch")
	}

	return nil
}

func (s *AttachmentService) validateSHA384Hash(hash string, data []byte) error {
	computedHash := sha512.Sum384(data)
	computedHashHex := hex.EncodeToString(computedHash[:])

	if computedHashHex != hash {
		return errors.New("hash mismatch")
	}

	return nil
}

func (s *AttachmentService) handleRemoteAttachment(
	ctx context.Context,
	attachment map[string]interface{},
) error {
	targetURL := fmt.Sprint(attachment[AttachmentDataField])
	if targetURL == "" {
		return errors.New("url is required")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to fetch url: %w", err)
	}

	var body []byte
	if resp.Body != nil {
		defer func() {
			_ = resp.Body.Close() // nolint
		}()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d and body %v", resp.StatusCode, string(body))
	}

	if err = s.validateHash(attachment, body); err != nil {
		return fmt.Errorf("failed to validate hash for remote attachment: %w", err)
	}

	attachment[AttachmentDataField] = fmt.Sprintf("data:%s;base64,%s",
		resp.Header.Get("Content-Type"),
		base64.StdEncoding.EncodeToString(body),
	)

	return nil
}

// nolint:gocognit
func (s *AttachmentService) findAttachments(
	targetMap map[string]interface{},
	types []string,
) []*attachmentData {
	var attachments []*attachmentData

	for k, v := range targetMap {
		switch valTyped := v.(type) {
		case []interface{}:
			for _, item := range valTyped {
				if nested, ok := item.(map[string]interface{}); ok {
					attachments = append(attachments, s.findAttachments(nested, types)...)
				}
			}
		case map[string]interface{}:
			attachments = append(attachments, s.findAttachments(valTyped, types)...)
		}

		if k != "type" && k != "@type" {
			continue
		}

		switch typed := v.(type) {
		case string:
			if lo.Contains(types, typed) {
				attachments = append(attachments, &attachmentData{
					Type:  typed,
					Claim: targetMap,
				})
			}
		case []interface{}:
			newSlice := make([]string, 0, len(typed))
			for _, item := range typed {
				newSlice = append(newSlice, fmt.Sprint(item))
			}

			for _, item := range newSlice {
				if lo.Contains(types, item) {
					attachments = append(attachments, &attachmentData{
						Type:  item,
						Claim: targetMap,
					})
				}
			}
		case []string:
			for _, item := range typed {
				if lo.Contains(types, item) {
					attachments = append(attachments, &attachmentData{
						Type:  item,
						Claim: targetMap,
					})
				}
			}
		}
	}

	return attachments
}
