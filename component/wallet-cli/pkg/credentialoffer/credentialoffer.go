package credentialoffer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	"github.com/valyala/fastjson"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func ParseInitiateIssuanceUrl(rawURL string, client *http.Client, vdrRegistry vdrapi.Registry) (*oidc4ci.CredentialOfferResponse, error) {
	initiateIssuanceURLParsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %w", err)
	}

	var offerResponse oidc4ci.CredentialOfferResponse
	var credentialOfferPayload []byte

	if credentialOfferQueryParam := initiateIssuanceURLParsed.Query().Get("credential_offer"); len(credentialOfferQueryParam) > 0 {
		credentialOfferPayload = []byte(credentialOfferQueryParam)
		// Depends on Issuer configuration, credentialOfferURL might be either JWT signed CredentialOfferResponse,
		// or encoded oidc4ci.CredentialOfferResponse itself.
		if jwt.IsJWS(credentialOfferQueryParam) {
			credentialOfferPayload, err = getCredentialOfferJWTPayload(credentialOfferQueryParam, vdrRegistry)
			if err != nil {
				return nil, err
			}
		}

		if err = json.Unmarshal(credentialOfferPayload, &offerResponse); err != nil {
			return nil, fmt.Errorf("can not parse credential offer. %w", err)
		}

		return &offerResponse, nil
	}

	remoteURI := initiateIssuanceURLParsed.Query().Get("credential_offer_uri")
	if remoteURI == "" {
		return nil, fmt.Errorf("credential_offer and credential_offer_uri are both empty")
	}

	resp, err := client.Get(remoteURI)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	credentialOfferPayload, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read credential_offer_uriresponse body: %w", err)
	}

	// Depends on Issuer configuration, rspBody might be either JWT signed CredentialOfferResponse,
	// or encoded oidc4ci.CredentialOfferResponse itself.
	if jwt.IsJWS(string(credentialOfferPayload)) {
		credentialOfferPayload, err = getCredentialOfferJWTPayload(string(credentialOfferPayload), vdrRegistry)
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
	jwtVerifier := jwt.NewVerifier(jwt.KeyResolverFunc(
		verifiable.NewVDRKeyResolver(vdrRegistry).PublicKeyFetcher()))

	_, credentialOfferPayload, err := jwt.Parse(
		rawResponse,
		jwt.WithSignatureVerifier(jwtVerifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential offer JWT: %w", err)
	}

	var fastParser fastjson.Parser
	v, err := fastParser.ParseBytes(credentialOfferPayload)
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	sb, err := v.Get("credential_offer").Object()
	if err != nil {
		return nil, fmt.Errorf("fastjson.Parser Get credential_offer: %w", err)
	}

	return sb.MarshalTo([]byte{}), nil
}
