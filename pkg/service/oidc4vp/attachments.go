/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination attachments_mocks_test.go -self_package mocks -package oidc4vp_test -source=attachments.go -mock_names httpClient=MockHttpClient

package oidc4vp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/util/maphelpers"
	"github.com/trustbloc/vc-go/verifiable"
)

const (
	AttachmentTypeRemote   = "RemoteAttachment"
	AttachmentTypeEmbedded = "EmbeddedAttachment"
	AttachmentDataField    = "uri"
)

var knownAttachmentTypes = []string{AttachmentTypeRemote, AttachmentTypeEmbedded}

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

func (s *AttachmentService) PrepareAttachments(
	ctx context.Context,
	subjects []*verifiable.Subject,
) ([]map[string]interface{}, error) {
	var allAttachments []*Attachment

	for _, subject := range subjects {
		allAttachments = append(allAttachments,
			s.findAttachments(subject.CustomFields, make([]*Attachment, 0))...,
		)
	}

	var final []map[string]interface{}

	for _, attachment := range allAttachments {
		cloned := maphelpers.CopyMap(attachment.Claim) // shallow copy
		final = append(final, cloned)

		if attachment.Type == AttachmentTypeRemote {
			go func() {
				err := s.handleRemoteAttachment(ctx, cloned)
				if err != nil {
					attachment.Claim["error"] = fmt.Sprintf("failed to handle remote attachment: %s", err)
				}
			}()
		}
	}

	return final, nil
}

func (s *AttachmentService) handleRemoteAttachment(
	ctx context.Context,
	attachment map[string]interface{},
) error {
	targetUrl := fmt.Sprint(attachment[AttachmentDataField])
	if targetUrl == "" {
		return errors.New("url is required")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to fetch url: %w", err)
	}

	var body []byte
	if resp.Body != nil {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d and body %v", resp.StatusCode, string(body))
	}

	attachment[AttachmentDataField] = base64.StdEncoding.EncodeToString(body) // todo prefix type

	return nil
}

func (s *AttachmentService) findAttachments(
	targetMap map[string]interface{},
	attachments []*Attachment,
) []*Attachment {
	hasAttachment := false
	for k, v := range targetMap {
		if nested, ok := v.(map[string]interface{}); ok {
			attachments = append(attachments, s.findAttachments(nested, attachments)...)
		}

		if hasAttachment {
			continue
		}

		if k != "type" && k != "@type" {
			continue
		}

		switch typed := v.(type) {
		case string:
			if lo.Contains(knownAttachmentTypes, typed) {
				attachments = append(attachments, &Attachment{
					Type:  typed,
					Claim: targetMap,
				})

				hasAttachment = true
			}
		case []interface{}:
			newSlice := make([]string, 0, len(typed))
			for _, item := range typed {
				newSlice = append(newSlice, fmt.Sprint(item))
			}

			for _, item := range newSlice {
				if lo.Contains(knownAttachmentTypes, item) {
					attachments = append(attachments, &Attachment{
						Type:  item,
						Claim: targetMap,
					})

					hasAttachment = true
				}
			}
		case []string:
			for _, item := range typed {
				if lo.Contains(knownAttachmentTypes, item) {
					attachments = append(attachments, &Attachment{
						Type:  item,
						Claim: targetMap,
					})

					hasAttachment = true
				}
			}
		}
	}

	return attachments
}
