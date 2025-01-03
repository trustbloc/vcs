/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifycredential

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	didconfig "github.com/trustbloc/vc-go/didconfig/client"
)

const (
	linkedDomainsService = "LinkedDomains"
)

type serviceEndpoint struct {
	Origins []string `json:"origins"`
}

func (s *Service) ValidateLinkedDomain(_ context.Context, issuerSigningDID string) error {
	didDocResolution, vdrErr := s.vdr.Resolve(issuerSigningDID)
	if vdrErr != nil {
		return fmt.Errorf("failed to resolve DID %s, err: %w", issuerSigningDID, vdrErr)
	}

	for _, service := range didDocResolution.DIDDocument.Service {
		serviceType := getServiceType(service.Type)
		if serviceType != linkedDomainsService {
			continue
		}

		serviceEndpointBytes, err := service.ServiceEndpoint.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to get LinkedDomains service endpoint: %w", err)
		}

		serviceEndpoint := &serviceEndpoint{}

		if err = json.Unmarshal(serviceEndpointBytes, serviceEndpoint); err != nil {
			return err
		}

		didConfigurationClient := didconfig.New(
			didconfig.WithJSONLDDocumentLoader(s.documentLoader),
			didconfig.WithVDRegistry(s.vdr),
			didconfig.WithHTTPClient(s.httpClient),
		)

		return didConfigurationClient.VerifyDIDAndDomain(issuerSigningDID,
			strings.TrimSuffix(serviceEndpoint.Origins[0], "/"))
	}

	return fmt.Errorf("no LinkedDomains service in DID %s", issuerSigningDID)
}

func getServiceType(serviceType interface{}) string {
	var val string

	switch t := serviceType.(type) {
	case string:
		val = t
	case []string:
		if len(t) > 0 {
			val = t[0]
		}
	case []interface{}:
		if len(t) > 0 {
			if str, ok := t[0].(string); ok {
				val = str
			}
		}
	}

	return val
}
