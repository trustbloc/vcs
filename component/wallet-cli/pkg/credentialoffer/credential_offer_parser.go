/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialoffer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/vermethod"
	"github.com/valyala/fastjson"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

// Parser parses credential offer.
type Parser struct {
	HTTPClient  *http.Client
	VDRRegistry vdrapi.Registry
}

func (p *Parser) Parse(credentialOfferURI string) (*oidc4ci.CredentialOfferResponse, error) {
	u, err := url.Parse(credentialOfferURI)
	if err != nil {
		return nil, fmt.Errorf("invalid credential offer uri: %w", err)
	}

	var offerResponse oidc4ci.CredentialOfferResponse
	var credentialOfferPayload []byte

	if credentialOfferQueryParam := u.Query().Get("credential_offer"); len(credentialOfferQueryParam) > 0 {
		credentialOfferPayload = []byte(credentialOfferQueryParam)
		// depending on issuer configuration, credentialOfferURL might be either JWT-signed CredentialOfferResponse,
		// or encoded CredentialOfferResponse itself.
		if jwt.IsJWS(credentialOfferQueryParam) {
			credentialOfferPayload, err = getCredentialOfferJWTPayload(credentialOfferQueryParam, p.VDRRegistry)
			if err != nil {
				return nil, err
			}
		}

		if err = json.Unmarshal(credentialOfferPayload, &offerResponse); err != nil {
			return nil, fmt.Errorf("unmarshal credential offer payload: %w", err)
		}

		return &offerResponse, nil
	}

	remoteURI := u.Query().Get("credential_offer_uri")
	if remoteURI == "" {
		return nil, fmt.Errorf("both credential_offer and credential_offer_uri are empty")
	}

	resp, err := p.HTTPClient.Get(remoteURI)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	credentialOfferPayload, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read credential_offer_uri response body: %w", err)
	}

	if jwt.IsJWS(string(credentialOfferPayload)) {
		credentialOfferPayload, err = getCredentialOfferJWTPayload(string(credentialOfferPayload), p.VDRRegistry)
		if err != nil {
			return nil, err
		}
	}

	if err = json.Unmarshal(credentialOfferPayload, &offerResponse); err != nil {
		return nil, err
	}

	return &offerResponse, nil
}

func getCredentialOfferJWTPayload(rawResponse string, vdrRegistry vdrapi.Registry) ([]byte, error) {
	jwtVerifier := defaults.NewDefaultProofChecker(vermethod.NewVDRResolver(vdrRegistry))

	_, credentialOfferPayload, err := jwt.ParseAndCheckProof(
		rawResponse,
		jwtVerifier, true,
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential offer JWT: %w", err)
	}

	var parser fastjson.Parser

	v, err := parser.ParseBytes(credentialOfferPayload)
	if err != nil {
		return nil, fmt.Errorf("decode credential offer payload: %w", err)
	}

	sb, err := v.Get("credential_offer").Object()
	if err != nil {
		return nil, fmt.Errorf("gGet credential_offer from payload: %w", err)
	}

	return sb.MarshalTo([]byte{}), nil
}
