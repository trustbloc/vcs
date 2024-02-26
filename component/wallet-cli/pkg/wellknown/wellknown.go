/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wellknown

import (
	"encoding/json"
	"fmt"
	"github.com/samber/lo"
	"io"
	"log/slog"
	"net/http"

	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/vermethod"
	"github.com/valyala/fastjson"

	issuerv1 "github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type Service struct {
	HTTPClient  *http.Client
	VDRRegistry vdrapi.Registry
	issuerDID   string
}

// GetWellKnownOpenIDConfiguration returns OIDC Configuration.
func (s *Service) GetWellKnownOpenIDConfiguration(
	issuerURL string,
) (*issuerv1.WellKnownOpenIDIssuerConfiguration, error) {
	slog.Info("Getting OpenID credential issuer configuration",
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

	var oidcConfigUnsigned issuerv1.WellKnownOpenIDIssuerConfiguration

	wellKnownOpenIDIssuerConfigurationPayload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read issuer configuration payload body: %w", err)
	}

	if err = json.Unmarshal(wellKnownOpenIDIssuerConfigurationPayload, &oidcConfigUnsigned); err != nil {
		return nil, fmt.Errorf("decode issuer well-known: %w", err)
	}

	signedMetadata := lo.FromPtr(oidcConfigUnsigned.SignedMetadata)

	if !jwt.IsJWS(signedMetadata) {
		return &oidcConfigUnsigned, nil
	}

	var issuerDID []byte

	wellKnownOpenIDIssuerConfigurationPayload, issuerDID, err = getWellKnownOpenIDConfigurationJWTPayload(
		signedMetadata, s.VDRRegistry)
	if err != nil {
		return nil, err
	}

	s.issuerDID = string(issuerDID)

	var oidcConfig issuerv1.WellKnownOpenIDIssuerConfiguration

	if err = json.Unmarshal(wellKnownOpenIDIssuerConfigurationPayload, &oidcConfig); err != nil {
		return nil, fmt.Errorf("decode issuer well-known: %w", err)
	}

	return &oidcConfig, nil
}

func getWellKnownOpenIDConfigurationJWTPayload(rawResponse string, vdrRegistry vdrapi.Registry) ([]byte, []byte, error) {
	jwtVerifier := defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(vdrRegistry))

	_, credentialOfferPayload, err := jwt.ParseAndCheckProof(
		rawResponse,
		jwtVerifier, true,
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("parse issuer configuration JWT: %w", err)
	}

	var fastParser fastjson.Parser
	v, err := fastParser.ParseBytes(credentialOfferPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("decode claims: %w", err)
	}

	return credentialOfferPayload, v.GetStringBytes("iss"), nil
}

func (s *Service) GetIssuerDID() string {
	return s.issuerDID
}
