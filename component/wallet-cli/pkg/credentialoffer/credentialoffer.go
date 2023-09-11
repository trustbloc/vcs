package credentialoffer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/valyala/fastjson"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

var errSignedCredentialOfferIsNotSupported = errors.New("credential offer is in JWT format, but it is not supported by configuration")

type Params struct {
	InitiateIssuanceURL               string
	Client                            *http.Client
	VDRRegistry                       vdrapi.Registry
	JWTSignedCredentialOfferSupported bool
}

func ParseInitiateIssuanceUrl(params *Params) (*oidc4ci.CredentialOfferResponse, error) {
	initiateIssuanceURLParsed, err := url.Parse(params.InitiateIssuanceURL)
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
			if !params.JWTSignedCredentialOfferSupported {
				return nil, errSignedCredentialOfferIsNotSupported
			}

			credentialOfferPayload, err = getCredentialOfferJWTPayload(credentialOfferQueryParam, params.VDRRegistry)
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

	resp, err := params.Client.Get(remoteURI)
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
		if !params.JWTSignedCredentialOfferSupported {
			return nil, errSignedCredentialOfferIsNotSupported
		}

		credentialOfferPayload, err = getCredentialOfferJWTPayload(string(credentialOfferPayload), params.VDRRegistry)
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
