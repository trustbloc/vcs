/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	methodCollectionsQuery = "CollectionsQuery"
	methodKey              = "method"
	objectIDKey            = "objectId"
	serviceTypeIdentityHub = "IdentityHub"
)

type IdentityHubRequest struct {
	RequestID string    `json:"requestId"`
	Target    string    `json:"target"`
	Messages  []Message `json:"messages"`
}

type Message struct {
	Descriptor map[string]interface{} `json:"descriptor"`
	Data       string                 `json:"data,omitempty"`
}

type IdentityHubResponse struct {
	RequestID string          `json:"requestId"`
	Status    *Status         `json:"status"`
	Replies   []MessageResult `json:"replies"`
}

type MessageResult struct {
	MessageID string    `json:"messageId"`
	Status    Status    `json:"status"`
	Entries   []Message `json:"entries,omitempty"`
}

type Status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type identityHubRequestMeta struct {
	objectID string
	payload  []byte
}

func (s *Service) resolveDIDRelativeURL(ctx context.Context, didRelativeURL string) ([]byte, error) {
	didDoc, err := s.resolveDID(didRelativeURL)
	if err != nil {
		return nil, err
	}

	queryValues, err := s.getQueryValues(didRelativeURL)
	if err != nil {
		return nil, err
	}

	requestMeta, err := s.getIdentityHubRequestMeta(didDoc.ID, queryValues)
	if err != nil {
		return nil, err
	}

	serviceEndpoint, err := s.getIdentityHubServiceEndpoint(didDoc)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, serviceEndpoint, bytes.NewReader(requestMeta.payload))
	if err != nil {
		return nil, fmt.Errorf("unable to create request to identity hub: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := s.sendHTTPRequest(req, http.StatusOK, s.requestTokens[cslRequestTokenName])
	if err != nil {
		return nil, fmt.Errorf("send request failed: %w", err)
	}

	var identityHubResponse IdentityHubResponse
	err = json.Unmarshal(resp, &identityHubResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal IdentityHubResponse: %w", err)
	}

	if err = identityHubResponse.checkResponseStatus(); err != nil {
		return nil, err
	}

	return identityHubResponse.GetVCBytes(requestMeta.objectID)
}

func (s *Service) getQueryValues(didRelativeURL string) (url.Values, error) {
	var err error
	var queryValues url.Values
	chunks := strings.Split(didRelativeURL, "?")
	if len(chunks) > 1 {
		queryValues, err = url.ParseQuery(chunks[1])
		if err != nil {
			return nil, fmt.Errorf("unable to parse query from didURL: %w", err)
		}
	}

	return queryValues, nil
}

func (s *Service) getIdentityHubServiceEndpoint(did *did.Doc) (string, error) {
	for _, service := range did.Service {
		if service.Type == serviceTypeIdentityHub {
			switch service.ServiceEndpoint.Type() {
			case model.Generic:
				serviceEndpoint, err := service.ServiceEndpoint.URI()
				if err == nil {
					return serviceEndpoint, nil
				}

				serviceEndpointBytes, err := service.ServiceEndpoint.MarshalJSON()
				if err != nil {
					return "", fmt.Errorf("unable to marshal DIDCore service endpoint: %w", err)
				}

				var mapped map[string]interface{}
				if err = json.Unmarshal(serviceEndpointBytes, &mapped); err != nil {
					return "", fmt.Errorf("unable to unmarshal DIDCore service endpoint: %w", err)
				}

				for _, v := range mapped {
					didCoreEndpoint := model.NewDIDCoreEndpoint(v)
					serviceEndpoint, err = didCoreEndpoint.URI()
					if err == nil {
						return serviceEndpoint, nil
					}
				}

				return "", fmt.Errorf("unable to extract DIDCore service endpoint")
			default:
				serviceEndpoint, err := service.ServiceEndpoint.URI()
				if err != nil {
					return "", fmt.Errorf("unable to get service endpoint URL: %w", err)
				}

				return serviceEndpoint, nil
			}
		}
	}

	return "", errors.New("no identity hub service supplied")
}

func (s *Service) resolveDID(didRelativeURL string) (*did.Doc, error) {
	didID := strings.Split(didRelativeURL, "?")[0]
	didResolution, err := s.vdr.Resolve(didID)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve did url: %w", err)
	}

	return didResolution.DIDDocument, nil
}

func (s *Service) getIdentityHubRequestMeta(didID string, queryValues url.Values) (*identityHubRequestMeta, error) {
	queriesDecoded, err := base64.StdEncoding.DecodeString(queryValues.Get("queries"))
	if err != nil {
		return nil, fmt.Errorf("unable to decode \"queries\" key: %w", err)
	}

	var mapped []map[string]interface{}
	if err = json.Unmarshal(queriesDecoded, &mapped); err != nil {
		return nil, fmt.Errorf("unable to unmarshal queries onto map: %w", err)
	}

	identityHubRequest := IdentityHubRequest{
		RequestID: uuid.NewString(),
		Target:    didID,
		Messages:  nil,
	}

	requestMeta := &identityHubRequestMeta{}
	var ok bool
	for _, mm := range mapped {
		msg := Message{Descriptor: mm}
		if !msg.IsMethod(methodCollectionsQuery) {
			continue
		}
		requestMeta.objectID, ok = msg.GetObjectID()
		if ok {
			identityHubRequest.Messages = append(identityHubRequest.Messages, msg)
			break
		}
	}

	if requestMeta.objectID == "" {
		return nil, fmt.Errorf("objectId is not defined, query %s", string(queriesDecoded))
	}

	requestMeta.payload, err = json.Marshal(identityHubRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal identityHubRequest: %w", err)
	}

	return requestMeta, nil
}

func (i IdentityHubResponse) checkResponseStatus() error {
	if i.Status != nil && i.Status.Code != http.StatusOK {
		return fmt.Errorf(
			"unexpected request level status code, got %d, message: %s",
			i.Status.Code,
			i.Status.Message,
		)
	}

	for _, messageResult := range i.Replies {
		if messageResult.Status.Code != http.StatusOK {
			return fmt.Errorf(
				"unexpected message level status code, got %d, message: %s",
				messageResult.Status.Code,
				messageResult.Status.Message,
			)
		}
	}

	return nil
}

func (i IdentityHubResponse) GetVCBytes(objectID string) ([]byte, error) {
	for _, messageResult := range i.Replies {
		for _, message := range messageResult.Entries {
			objectIDReceived, ok := message.GetObjectID()
			if !ok || !strings.EqualFold(objectIDReceived, objectID) {
				continue
			}

			vcBytesDecoded, err := base64.StdEncoding.DecodeString(message.Data)
			if err != nil {
				return nil, fmt.Errorf("unable to decode vc bytes: %w", err)
			}

			return vcBytesDecoded, nil
		}
	}

	return nil, fmt.Errorf("unable to get VC from IdentityHubResponse")
}

func (m Message) GetObjectID() (string, bool) {
	val, ok := m.Descriptor[objectIDKey].(string)
	return val, ok
}

func (m Message) IsMethod(method string) bool {
	v, ok := m.Descriptor[methodKey].(string)
	return ok && strings.EqualFold(v, method)
}
