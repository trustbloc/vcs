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
	"sync"

	"github.com/samber/lo"
	"github.com/trustbloc/vc-go/util/maphelpers"
	"github.com/trustbloc/vc-go/verifiable"
)

const (
	AttachmentTypeRemote   = "RemoteAttachment"
	AttachmentTypeEmbedded = "EmbeddedAttachment"
	AttachmentDataField    = "uri"
)

var knownAttachmentTypes = []string{AttachmentTypeRemote, AttachmentTypeEmbedded} // nolint:gochecknoglobals

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

func (s *AttachmentService) GetAttachments(
	ctx context.Context,
	subjects []verifiable.Subject,
) ([]map[string]interface{}, error) {
	var allAttachments []*Attachment

	for _, subject := range subjects {
		allAttachments = append(allAttachments,
			s.findAttachments(subject.CustomFields)...,
		)
	}

	if len(allAttachments) == 0 {
		return nil, nil
	}

	var final []map[string]interface{}

	var wg sync.WaitGroup
	for _, attachment := range allAttachments {
		cloned := maphelpers.CopyMap(attachment.Claim)
		attachment.Claim = cloned

		final = append(final, attachment.Claim)

		if attachment.Type == AttachmentTypeRemote {
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := s.handleRemoteAttachment(ctx, cloned)
				if err != nil {
					cloned["error"] = fmt.Sprintf("failed to handle remote attachment: %s", err)
				}
			}()
		}
	}
	wg.Wait()

	return final, nil
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

	attachment[AttachmentDataField] = fmt.Sprintf("data:%s;base64,%s",
		resp.Header.Get("Content-Type"),
		base64.StdEncoding.EncodeToString(body),
	)

	return nil
}

// nolint:gocognit
func (s *AttachmentService) findAttachments(
	targetMap map[string]interface{},
) []*Attachment {
	var attachments []*Attachment

	for k, v := range targetMap {
		switch valTyped := v.(type) {
		case []interface{}:
			for _, item := range valTyped {
				if nested, ok := item.(map[string]interface{}); ok {
					attachments = append(attachments, s.findAttachments(nested)...)
				}
			}
		case map[string]interface{}:
			attachments = append(attachments, s.findAttachments(valTyped)...)
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
				}
			}
		case []string:
			for _, item := range typed {
				if lo.Contains(knownAttachmentTypes, item) {
					attachments = append(attachments, &Attachment{
						Type:  item,
						Claim: targetMap,
					})
				}
			}
		}
	}

	return attachments
}
