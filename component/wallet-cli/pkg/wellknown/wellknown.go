/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wellknown

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/valyala/fastjson"

	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type Service struct {
	HTTPClient  *http.Client
	VDRRegistry vdrapi.Registry
}

// GetWellKnownOpenIDConfiguration returns OIDC Configuration.
func (s *Service) GetWellKnownOpenIDConfiguration(
	issuerURL string,
) (*issuerv1.WellKnownOpenIDIssuerConfiguration, error) {
	slog.Info("getting OpenID credential issuer configuration",
		"url", issuerURL+"/.well-known/openid-credential-issuer",
	)

	resp, err := s.HTTPClient.Get(issuerURL + "/.well-known/openid-credential-issuer")
	if err != nil {
		return nil, fmt.Errorf("get issuer well-known: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get issuer well-known: status code %d", resp.StatusCode)
	}

	var oidcConfig issuerv1.WellKnownOpenIDIssuerConfiguration

	wellKnownOpenIDIssuerConfigurationPayload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read issuer configuration payload body: %w", err)
	}

	if jwt.IsJWS(string(wellKnownOpenIDIssuerConfigurationPayload)) {
		wellKnownOpenIDIssuerConfigurationPayload, err =
			getWellKnownOpenIDConfigurationJWTPayload(
				string(wellKnownOpenIDIssuerConfigurationPayload), s.VDRRegistry)
		if err != nil {
			return nil, err
		}
	}

	if err = json.Unmarshal(wellKnownOpenIDIssuerConfigurationPayload, &oidcConfig); err != nil {
		return nil, fmt.Errorf("decode issuer well-known: %w", err)
	}

	return &oidcConfig, nil
}

func getWellKnownOpenIDConfigurationJWTPayload(rawResponse string, vdrRegistry vdrapi.Registry) ([]byte, error) {
	jwtVerifier := jwt.NewVerifier(jwt.KeyResolverFunc(
		verifiable.NewVDRKeyResolver(vdrRegistry).PublicKeyFetcher()))

	_, credentialOfferPayload, err := jwt.Parse(
		rawResponse,
		jwt.WithSignatureVerifier(jwtVerifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse issuer configuration JWT: %w", err)
	}

	var fastParser fastjson.Parser
	v, err := fastParser.ParseBytes(credentialOfferPayload)
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	sb, err := v.Get("well_known_openid_issuer_configuration").Object()
	if err != nil {
		return nil, fmt.Errorf("fastjson.Parser Get well_known_openid_issuer_configuration: %w", err)
	}

	return sb.MarshalTo([]byte{}), nil
}
