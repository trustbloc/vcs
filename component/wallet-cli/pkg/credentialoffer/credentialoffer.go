package credentialoffer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

func ParseInitiateIssuanceUrl(rawURL string, client *http.Client) (*oidc4ci.CredentialOfferResponse, error) {
	initiateIssuanceURLParsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %w", err)
	}

	credentialOfferURL := initiateIssuanceURLParsed.Query().Get("credential_offer")
	var offerResponse oidc4ci.CredentialOfferResponse

	if len(credentialOfferURL) > 0 {
		if err = json.Unmarshal([]byte(credentialOfferURL), &offerResponse); err != nil {
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
	if err = json.NewDecoder(resp.Body).Decode(&offerResponse); err != nil {
		return nil, err
	}

	return &offerResponse, nil
}
