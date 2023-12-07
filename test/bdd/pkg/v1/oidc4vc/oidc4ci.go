/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/samber/lo"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/model"
)

const (
	vcsAPIGateway                       = "https://api-gateway.trustbloc.local:5566"
	initiateCredentialIssuanceURLFormat = vcsAPIGateway + "/issuer/profiles/%s/%s/interactions/initiate-oidc"
	issueCredentialURLFormat            = vcsAPIGateway + "/issuer/profiles/%s/%s/credentials/issue"
	issuedCredentialHistoryURL          = vcsAPIGateway + "/issuer/profiles/%s/issued-credentials"
	vcsIssuerURL                        = vcsAPIGateway + "/oidc/idp/%s/%s"
	oidcProviderURL                     = "http://cognito-auth.local:8094/cognito"
	claimDataURL                        = "https://mock-login-consent.example.com:8099/claim-data"
)

func (s *Steps) authorizeIssuerProfileUser(profileVersionedID, username, password string) error {
	if err := s.ResetAndSetup(); err != nil {
		return err
	}
	issuerProfile, ok := s.bddContext.IssuerProfiles[profileVersionedID]

	if !ok {
		return fmt.Errorf("issuer profile '%s' not found", profileVersionedID)
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL,
		username, password, []string{"org_admin"})
	if err != nil {
		return err
	}

	s.bddContext.Args[getOrgAuthTokenKey(issuerProfile.ID+"/"+issuerProfile.Version)] = accessToken

	s.issuerProfile = issuerProfile
	return nil
}

func (s *Steps) initiateCredentialIssuance(initiateOIDC4CIRequest initiateOIDC4CIRequest) (*initiateOIDC4CIResponse, error) {
	endpointURL := fmt.Sprintf(initiateCredentialIssuanceURLFormat, s.issuerProfile.ID, s.issuerProfile.Version)

	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuerProfile.ID+"/"+s.issuerProfile.Version)]

	reqBody, err := json.Marshal(initiateOIDC4CIRequest)
	if err != nil {
		return nil, fmt.Errorf("marshal initiate oidc4vc req: %w", err)
	}

	resp, err := bddutil.HTTPSDo(http.MethodPost, endpointURL, "application/json", token, bytes.NewReader(reqBody),
		s.bddContext.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("https do: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, b)
	}

	var r *initiateOIDC4CIResponse

	if err = json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("unmarshal initiate oidc4vc resp: %w", err)
	}

	if err = s.checkInitiateIssuanceURL(r.OfferCredentialURL); err != nil {
		return nil, err
	}

	return r, nil
}

func (s *Steps) checkInitiateIssuanceURL(initiateIssuanceURL string) error {
	if initiateIssuanceURL == "" {
		return fmt.Errorf("initiate issuance URL is empty")
	}

	if _, err := url.Parse(initiateIssuanceURL); err != nil {
		return fmt.Errorf("parse initiate issuance URL: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIPreAuth(initiateOIDC4CIRequest initiateOIDC4CIRequest) error {
	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(initiateOIDC4CIRequest)
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}

	_, err = s.walletRunner.RunOIDC4CIPreAuth(
		&walletrunner.OIDC4VCIConfig{
			CredentialOfferURI: initiateOIDC4CIResponseData.OfferCredentialURL,
			CredentialType:     s.issuedCredentialType,
			CredentialFormat:   s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
			Pin:                *initiateOIDC4CIResponseData.UserPin,
		}, nil)
	if err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4CIPreAuth: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIPreAuthWithInvalidClaims() error {
	initiateIssuanceRequest := initiateOIDC4CIRequest{
		CredentialTemplateId: "universityDegreeTemplateID",
		ClaimData: &map[string]interface{}{
			"degree": map[string]string{
				"type":   "BachelorDegree",
				"degree": "MIT",
			},
			"name":               "Jayden Doe",
			"spouse":             "did:example:c276e12ec21ebfeb1f712ebc6f1",
			"totallyRandomField": "abcd",
		},
		UserPinRequired: true,
	}

	err := s.runOIDC4CIPreAuth(initiateIssuanceRequest)
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (s *Steps) initiateCredentialIssuanceWithClaimsSchemaValidationError() error {
	initiateIssuanceRequest := initiateOIDC4CIRequest{
		CredentialTemplateId: "universityDegreeTemplateID",
		ClaimData: &map[string]interface{}{
			"degree": map[string]string{
				"degree": "MIT",
			},
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
		},
		UserPinRequired: true,
	}

	_, err := s.initiateCredentialIssuance(initiateIssuanceRequest)
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), "validation error: [(root): name is required; degree: type is required]") {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (s *Steps) fetchClaimData(issuedCredentialType string) (map[string]interface{}, error) {
	resp, err := bddutil.HTTPSDo(
		http.MethodPost,
		claimDataURL+"?credentialType="+issuedCredentialType,
		"application/json",
		"", nil, s.tlsConfig) //nolint: bodyclose
	if err != nil {
		return nil, err
	}
	defer bddutil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBytes)
	}

	var claims map[string]interface{}
	if err = json.Unmarshal(respBytes, &claims); err != nil {
		return nil, fmt.Errorf("decode response payload: %w", err)
	}

	return claims, nil
}

func (s *Steps) runOIDC4CIPreAuthWithValidClaims() error {
	claims, err := s.fetchClaimData(s.issuedCredentialType)
	if err != nil {
		return fmt.Errorf("fetchClaimData: %w", err)
	}

	initiateIssuanceRequest := initiateOIDC4CIRequest{
		CredentialTemplateId: s.issuedCredentialTemplateID,
		ClaimData:            &claims,
		UserPinRequired:      true,
	}

	return s.runOIDC4CIPreAuth(initiateIssuanceRequest)
}

func (s *Steps) runOIDC4CIPreAuthWithClientAttestation() error {
	if err := s.walletRunner.CreateWallet(); err != nil {
		return fmt.Errorf("create wallet: %w", err)
	}

	if err := s.addAttestationVC(); err != nil {
		return fmt.Errorf("add attestation vc to wallet: %w", err)
	}

	claims, err := s.fetchClaimData(s.issuedCredentialType)
	if err != nil {
		return fmt.Errorf("fetchClaimData: %w", err)
	}

	initiateIssuanceRequest := initiateOIDC4CIRequest{
		CredentialTemplateId: s.issuedCredentialTemplateID,
		ClaimData:            &claims,
		UserPinRequired:      true,
	}

	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(initiateIssuanceRequest)
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}

	_, err = s.walletRunner.RunOIDC4CIPreAuth(
		&walletrunner.OIDC4VCIConfig{
			CredentialOfferURI:      initiateOIDC4CIResponseData.OfferCredentialURL,
			CredentialType:          s.issuedCredentialType,
			CredentialFormat:        s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
			Pin:                     *initiateOIDC4CIResponseData.UserPin,
			EnableClientAttestation: true,
		}, nil)
	if err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4CIPreAuth: %w", err)
	}

	return nil
}

func (s *Steps) addAttestationVC() error {
	vcc := verifiable.CredentialContents{
		Context: []string{
			verifiable.ContextURI,
			"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		},
		ID: uuid.New().String(),
		Types: []string{
			verifiable.VCType,
			"WalletAttestationCredential",
		},
		Subject: []verifiable.Subject{
			{
				ID: s.walletRunner.GetVCProviderConf().WalletParams.DidID[0],
			},
		},
		Issuer: &verifiable.Issuer{
			ID: s.walletRunner.GetVCProviderConf().WalletParams.DidID[0],
		},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Expired: &utiltime.TimeWrapper{
			Time: time.Now().Add(time.Hour),
		},
	}

	vc, err := verifiable.CreateCredential(vcc, nil)
	if err != nil {
		return fmt.Errorf("create attestation vc: %w", err)
	}

	var vcOIDCFormat vcsverifiable.OIDCFormat

	switch s.issuerProfile.VCConfig.Format {
	case vcsverifiable.Jwt:
		vcOIDCFormat = vcsverifiable.JwtVCJson
	case vcsverifiable.Ldp:
		vcOIDCFormat = vcsverifiable.LdpVC
	default:
		return fmt.Errorf("unsupported vc format: %s", s.issuerProfile.VCConfig.Format)
	}

	reqData, err := vcprovider.GetIssueCredentialRequestData(vc, vcOIDCFormat)
	if err != nil {
		return fmt.Errorf("get issue credential request data: %w", err)
	}

	req := &model.IssueCredentialData{
		Credential: reqData,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := bddutil.HTTPSDo(
		http.MethodPost,
		fmt.Sprintf(issueCredentialURLFormat, s.issuerProfile.ID, s.issuerProfile.Version),
		"application/json",
		s.bddContext.Args[getOrgAuthTokenKey(fmt.Sprintf("%s/%s", s.issuerProfile.ID, s.issuerProfile.Version))],
		bytes.NewBuffer(body),
		s.tlsConfig,
	)
	if err != nil {
		return err
	}

	defer bddutil.CloseResponseBody(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, respBody)
	}

	return s.walletRunner.SaveCredentialInWallet(respBody)
}

func (s *Steps) runOIDC4CIPreAuthWithError(errorContains string) error {
	err := s.runOIDC4CIPreAuthWithValidClaims()
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error on runOIDC4CIPreAuthWithError: %w", err)
	}

	return nil
}

func (s *Steps) credentialTypeTemplateID(issuedCredentialType, issuedCredentialTemplateID string) error {
	s.issuedCredentialType = issuedCredentialType
	s.issuedCredentialTemplateID = issuedCredentialTemplateID

	return nil
}

func (s *Steps) runOIDC4CIAuthWithErrorInvalidClient(updatedClientID, errorContains string) error {
	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequest())
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}

	err = s.walletRunner.RunOIDC4VCI(&walletrunner.OIDC4VCIConfig{
		CredentialOfferURI: initiateOIDC4CIResponseData.OfferCredentialURL,
		ClientID:           "oidc4vc_client",
		Scopes:             []string{"openid", "profile"},
		RedirectURI:        "http://127.0.0.1/callback",
		CredentialType:     s.issuedCredentialType,
		CredentialFormat:   s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
		Login:              "bdd-test",
		Password:           "bdd-test-pass",
	}, &walletrunner.Hooks{
		BeforeTokenRequest: []walletrunner.OauthClientOpt{
			walletrunner.WithClientID(updatedClientID),
		}})

	if err == nil {
		return fmt.Errorf("error expected, got nil")
	}

	switch errorContains {
	case fosite.ErrInvalidClient.ErrorField:
		var oauthError *oauth2.RetrieveError
		if !errors.As(err, &oauthError) {
			return fmt.Errorf("unexpected err type: %w", err)
		}

		if oauthError.Response.StatusCode != http.StatusUnauthorized {
			return fmt.Errorf("unexpected status code %d", oauthError.Response.StatusCode)
		}

		var rfcError fosite.RFC6749Error
		if err = json.Unmarshal(oauthError.Body, &rfcError); err != nil {
			return fmt.Errorf("unmarshal RFC6749Error: %w", err)
		}

		if rfcError.ErrorField != errorContains {
			return fmt.Errorf("unexpected ErrorField: %w", rfcError.ErrorField)
		}

	default:
		return fmt.Errorf("unexpected err: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIAuthWithErrorInvalidSigningKeyID(errorContains string) error {
	return s.runOIDC4CIAuthWithErrorInvalidSignature(
		[]walletrunner.CredentialRequestOpt{
			walletrunner.WithSignerKeyID("didID#keyID"),
		},
		errorContains,
	)
}

func (s *Steps) runOIDC4CIAuthWithErrorInvalidSignatureValue(errorContains string) error {
	return s.runOIDC4CIAuthWithErrorInvalidSignature(
		[]walletrunner.CredentialRequestOpt{
			walletrunner.WithSignatureValue(uuid.NewString()),
		},
		errorContains,
	)
}

func (s *Steps) runOIDC4CIAuthWithErrorInvalidNonce(errorContains string) error {
	return s.runOIDC4CIAuthWithErrorInvalidSignature(
		[]walletrunner.CredentialRequestOpt{
			walletrunner.WithNonce(uuid.NewString()),
		},
		errorContains,
	)
}

func (s *Steps) runOIDC4CIAuthWithErrorInvalidSignature(beforeCredentialRequestOpts []walletrunner.CredentialRequestOpt, errorContains string) error {
	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequest())
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}

	err = s.walletRunner.RunOIDC4VCI(&walletrunner.OIDC4VCIConfig{
		CredentialOfferURI: initiateOIDC4CIResponseData.OfferCredentialURL,
		ClientID:           "oidc4vc_client",
		Scopes:             []string{"openid", "profile"},
		RedirectURI:        "http://127.0.0.1/callback",
		CredentialType:     s.issuedCredentialType,
		CredentialFormat:   s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
		Login:              "bdd-test",
		Password:           "bdd-test-pass",
	}, &walletrunner.Hooks{
		BeforeCredentialRequest: beforeCredentialRequestOpts,
	})

	if err == nil {
		return fmt.Errorf("error expected, got nil")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected err: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIAuth() error {
	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequest())
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}

	err = s.walletRunner.RunOIDC4VCI(&walletrunner.OIDC4VCIConfig{
		CredentialOfferURI: initiateOIDC4CIResponseData.OfferCredentialURL,
		ClientID:           "oidc4vc_client",
		Scopes:             []string{"openid", "profile"},
		RedirectURI:        "http://127.0.0.1/callback",
		CredentialType:     s.issuedCredentialType,
		CredentialFormat:   s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
		Login:              "bdd-test",
		Password:           "bdd-test-pass",
	}, nil)
	if err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4VCI: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIAuthWalletInitiatedFlow() error {
	err := s.walletRunner.RunOIDC4CIWalletInitiated(&walletrunner.OIDC4VCIConfig{
		ClientID:         "oidc4vc_client",
		Scopes:           []string{"openid", "profile"},
		RedirectURI:      "http://127.0.0.1/callback",
		CredentialType:   s.issuedCredentialType,
		CredentialFormat: s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
		Login:            "bdd-test",
		Password:         "bdd-test-pass",
		IssuerState:      fmt.Sprintf(vcsIssuerURL, s.issuerProfile.ID, s.issuerProfile.Version),
	}, nil)
	if err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4CIWalletInitiated: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIAuthWithInvalidClaims() error {
	s.issuedCredentialType = "UniversityDegreeCredential"
	s.issuedCredentialTemplateID = "universityDegreeTemplateID"

	claims := map[string]interface{}{
		"degree": map[string]string{
			"degree": "MIT",
		},
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
	}

	claimsDataBytes, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("marshal claims: %w", err)
	}

	issuanceReq := s.getInitiateIssuanceRequest()
	issuanceReq.ClaimEndpoint += fmt.Sprintf("&claim_data=%s", base64.URLEncoding.EncodeToString(claimsDataBytes))

	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(issuanceReq)
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}

	err = s.walletRunner.RunOIDC4VCI(&walletrunner.OIDC4VCIConfig{
		CredentialOfferURI: initiateOIDC4CIResponseData.OfferCredentialURL,
		ClientID:           "oidc4vc_client",
		Scopes:             []string{"openid", "profile"},
		RedirectURI:        "http://127.0.0.1/callback",
		CredentialType:     s.issuedCredentialType,
		CredentialFormat:   s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
		Login:              "bdd-test",
		Password:           "bdd-test-pass",
	}, nil)
	if err == nil {
		return fmt.Errorf("error expected, got nil")
	}

	if !strings.Contains(err.Error(), "validation error: [(root): name is required; degree: type is required]") {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIAuthWithClientRegistrationMethod(method string) error {
	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequest())
	if err != nil {
		return fmt.Errorf("initiateCredentialIssuance: %w", err)
	}
	config := &walletrunner.OIDC4VCIConfig{
		CredentialOfferURI: initiateOIDC4CIResponseData.OfferCredentialURL,
		Scopes:             []string{"openid", "profile"},
		RedirectURI:        "http://127.0.0.1/callback",
		CredentialType:     s.issuedCredentialType,
		CredentialFormat:   s.issuerProfile.CredentialMetaData.CredentialsSupported[0]["format"].(string),
		Login:              "bdd-test",
		Password:           "bdd-test-pass",
	}

	switch method {
	case "pre-registered":
		config.ClientID = "oidc4vc_client"
	case "dynamic":
		clientID, regErr := s.registerOAuthClient(initiateOIDC4CIResponseData.OfferCredentialURL)
		if regErr != nil {
			return fmt.Errorf("register oauth client: %w", err)
		}

		config.ClientID = clientID
	case "discoverable":
		config.ClientID = "https://file-server.trustbloc.local:10096"
		config.EnableDiscoverableClientID = true
	default:
		return fmt.Errorf("unsupported client registration method: %s", method)
	}

	if err = s.walletRunner.RunOIDC4VCI(config, nil); err != nil {
		return fmt.Errorf("s.walletRunner.RunOIDC4VCI: %w", err)
	}

	return nil
}

func (s *Steps) registerOAuthClient(offerCredentialURL string) (string, error) {
	u, err := url.Parse(offerCredentialURL)
	if err != nil {
		return "", fmt.Errorf("parse offer credential url: %w", err)
	}

	param := u.Query().Get("credential_offer")
	if param == "" {
		return "", fmt.Errorf("credential_offer param not found")
	}

	var offer credentialOfferResponse

	if err = json.Unmarshal([]byte(param), &offer); err != nil {
		return "", fmt.Errorf("unmarshal credential offer: %w", err)
	}

	openIDConfig, err := s.walletRunner.GetWellKnownOpenIDConfiguration(offer.CredentialIssuer)
	if err != nil {
		return "", fmt.Errorf("get openid well-known config: %w", err)
	}

	body, err := json.Marshal(
		&clientRegistrationRequest{
			GrantTypes:              lo.ToPtr([]string{"authorization_code"}),
			RedirectUris:            lo.ToPtr([]string{"http://127.0.0.1/callback"}),
			Scope:                   lo.ToPtr("openid profile"),
			TokenEndpointAuthMethod: lo.ToPtr("none"),
		},
	)

	resp, err := bddutil.HTTPSDo(http.MethodPost, lo.FromPtr(openIDConfig.RegistrationEndpoint), "application/json", "",
		bytes.NewReader(body), s.bddContext.TLSConfig)
	if err != nil {
		return "", fmt.Errorf("register dynamic client request: %w", err)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read register dynamic client response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", bddutil.ExpectedStatusCodeError(http.StatusCreated, resp.StatusCode, b)
	}

	var r *clientRegistrationResponse

	if err = json.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("unmarshal client registration response: %w", err)
	}

	return r.ClientId, nil
}

func (s *Steps) getInitiateIssuanceRequest() initiateOIDC4CIRequest {
	return initiateOIDC4CIRequest{
		ClaimEndpoint:        claimDataURL + "?credentialType=" + s.issuedCredentialType,
		CredentialTemplateId: s.issuedCredentialTemplateID,
		GrantType:            "authorization_code",
		OpState:              uuid.New().String(),
		ResponseType:         "code",
		Scope:                []string{"openid", "profile"},
		UserPinRequired:      false,
	}
}

func getOrgAuthTokenKey(org string) string {
	return org + "-accessToken"
}

func (s *Steps) checkIssuedCredential() error {
	credentialMap, err := s.walletRunner.GetWallet().GetAll()
	if err != nil {
		return fmt.Errorf("wallet.GetAll(): %w", err)
	}

	var vcParsed *verifiable.Credential

	for _, vcBytes := range credentialMap {
		vcParsed, err = verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(s.dl))
		if err != nil {
			return fmt.Errorf("parse credential from wallet: %w", err)
		}

		if err = s.checkVC(vcParsed); err != nil {
			return fmt.Errorf("checkVC: %w", err)
		}

		break
	}

	return s.checkIssuedCredentialHistory(vcParsed, true)
}

func (s *Steps) checkIssuedCredentialHistory(credential *verifiable.Credential, oidcFlow bool) error {
	// If credential status is disabled - history will not be stored.
	if s.issuerProfile.VCConfig.Status.Disable ||
		lo.Contains(credential.Contents().Types, "WalletAttestationCredential") {
		return nil
	}

	endpointURL := fmt.Sprintf(issuedCredentialHistoryURL, s.issuerProfile.ID)

	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuerProfile.ID+"/"+s.issuerProfile.Version)]

	resp, err := bddutil.HTTPSDo(http.MethodGet, endpointURL, "application/json", token, nil, s.bddContext.TLSConfig)
	if err != nil {
		return fmt.Errorf("checkIssuedCredentialHistory: https do: %w", err)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("checkIssuedCredentialHistory: read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return bddutil.ExpectedStatusCodeError(http.StatusOK, resp.StatusCode, b)
	}

	defer bddutil.CloseResponseBody(resp.Body)

	var r []credentialIssuanceHistoryData
	err = json.Unmarshal(b, &r)
	if err != nil {
		return fmt.Errorf("checkIssuedCredentialHistory: read response body: %w", err)
	}

	historyRecord, exist := lo.Find(r, func(item credentialIssuanceHistoryData) bool {
		return item.CredentialId == credential.Contents().ID
	})

	if !exist {
		return fmt.Errorf(
			"credential history response does not contain record with credentialID %s", credential.Contents().ID)
	}

	if !reflect.DeepEqual(historyRecord.CredentialTypes, credential.Contents().Types) {
		return fmt.Errorf("CredentialTypes are not equal")
	}

	if credential.Contents().Issuer.ID != historyRecord.Issuer {
		return fmt.Errorf("issuerID is different, expected: %s, got %s", credential.Contents().Issuer.ID, historyRecord.Issuer)
	}

	if (historyRecord.TransactionId == "") == oidcFlow {
		return fmt.Errorf("transactionId is nil, but value expected for OIDC flow")
	}

	var iss, exp string
	if credential.Contents().Issued != nil {
		iss = credential.Contents().Issued.Time.Format(time.RFC3339)
	}

	if credential.Contents().Expired != nil {
		exp = credential.Contents().Expired.Time.Format(time.RFC3339)
	}

	if historyRecord.IssuanceDate != iss {
		return fmt.Errorf("issuanceDate is different, expected: %s, got %s", iss, historyRecord.IssuanceDate)
	}

	if historyRecord.ExpirationDate != exp {
		return fmt.Errorf("expirationDate is different, expected: %s, got %s", exp, historyRecord.ExpirationDate)
	}

	return nil
}

func (s *Steps) checkIssuedCredentialHistoryStep() error {
	vcParsed, err := verifiable.ParseCredential(s.bddContext.CreatedCredential,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.dl))
	if err != nil {
		return fmt.Errorf("checkIssuedCredentialHistoryStep: %w", err)
	}

	return s.checkIssuedCredentialHistory(vcParsed, false)
}

func (s *Steps) checkVC(vc *verifiable.Credential) error {
	expectedStatusType := s.issuerProfile.VCConfig.Status.Type
	err := checkCredentialStatusType(vc, string(expectedStatusType))
	if err != nil {
		return err
	}

	err = checkIssuer(vc, s.issuerProfile.Name)
	if err != nil {
		return err
	}

	switch s.issuerProfile.VCConfig.Format {
	case vcsverifiable.Ldp:
		return s.checkSignatureHolder(vc)
	case vcsverifiable.Jwt:
		return s.checkJWT(vc)
	}

	return nil
}

func (s *Steps) checkJWT(vc *verifiable.Credential) error {
	if !vc.IsJWT() {
		return errors.New("JWT is empty")
	}

	if (vc.Contents().SDJWTHashAlg == nil) == s.issuerProfile.VCConfig.SDJWT.Enable {
		return errors.New("vc.SDJWTHashAlg is empty")
	}
	if (len(vc.SDJWTDisclosures()) == 0) == s.issuerProfile.VCConfig.SDJWT.Enable {
		return errors.New("vc.SDJWTDisclosures is empty")
	}

	return nil
}

func (s *Steps) checkSignatureHolder(vc *verifiable.Credential) error {
	if len(vc.Proofs()) < 1 {
		return errors.New("unexpected proofs amount")
	}

	switch s.issuerProfile.VCConfig.SignatureRepresentation {
	case verifiable.SignatureJWS:
		_, found := vc.Proofs()[0]["jws"]
		if !found {
			return fmt.Errorf("unable to find jws in proof")
		}
	case verifiable.SignatureProofValue:
		_, found := vc.Proofs()[0]["proofValue"]
		if !found {
			return fmt.Errorf("unable to find proofValue in proof")
		}
	default:
		return fmt.Errorf("unexpected signature representation in profile")
	}

	return nil
}

func (s *Steps) saveCredentials() error {
	for _, cred := range s.bddContext.CreatedCredentialsSet {
		err := s.walletRunner.SaveCredentialInWallet(cred)
		if err != nil {
			return fmt.Errorf("wallet add credential failed: %w", err)
		}
	}

	return nil
}

func (s *Steps) saveCredentialsInWallet() error {
	for _, cred := range s.bddContext.CreatedCredentialsSet {
		err := s.walletRunner.SaveCredentialInWallet(cred)
		if err != nil {
			return fmt.Errorf("wallet add credential failed: %w", err)
		}
	}

	return nil
}

func (s *Steps) initiateCredentialIssuanceWithError(errorContains string) error {
	_, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequest())

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error on initiateCredentialIssuance: %w", err)
	}

	return nil
}

func checkCredentialStatusType(vc *verifiable.Credential, expected string) error {
	if vc.Contents().Status.Type != expected {
		return bddutil.ExpectedStringError(expected, vc.Contents().Status.Type)
	}

	return nil
}

func checkIssuer(vc *verifiable.Credential, expected string) error {
	if vc.Contents().Issuer.CustomFields["name"] != expected {
		return bddutil.ExpectedStringError(expected, vc.Contents().Issuer.CustomFields["name"].(string))
	}

	return nil
}
