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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/oidc4vci"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/trustregistry"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wellknown"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

const (
	vcsAPIGateway                       = "https://api-gateway.trustbloc.local:5566"
	initiateCredentialIssuanceURLFormat = vcsAPIGateway + "/issuer/profiles/%s/%s/interactions/initiate-oidc"
	issuedCredentialHistoryURL          = vcsAPIGateway + "/issuer/profiles/%s/issued-credentials"
	vcsIssuerURL                        = vcsAPIGateway + "/oidc/idp/%s/%s"
	oidcProviderURL                     = "http://cognito-auth.local:8094/cognito"
	claimDataURL                        = "https://mock-login-consent.example.com:8099/claim-data"
	preAuthorizedCodeGrantType          = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
	authorizedCodeGrantType             = "authorization_code"
)

func (s *Steps) authorizeIssuerProfileUser(profileVersionedID, username, password string) error {
	if err := s.ResetAndSetup(); err != nil {
		return err
	}

	issuerProfile, ok := s.bddContext.IssuerProfiles[profileVersionedID]
	if !ok {
		return fmt.Errorf("issuer profile '%s' not found", profileVersionedID)
	}

	accessToken, err := bddutil.IssueAccessToken(context.Background(), oidcProviderURL, username, password,
		[]string{"org_admin"})
	if err != nil {
		return err
	}

	s.bddContext.Args[getOrgAuthTokenKey(issuerProfile.ID+"/"+issuerProfile.Version)] = accessToken
	s.issuerProfile = issuerProfile

	return nil
}

func (s *Steps) initiateCredentialIssuance(req initiateOIDC4VCIRequest) (*initiateOIDC4VCIResponse, error) {
	endpointURL := fmt.Sprintf(initiateCredentialIssuanceURLFormat, s.issuerProfile.ID, s.issuerProfile.Version)

	token := s.bddContext.Args[getOrgAuthTokenKey(s.issuerProfile.ID+"/"+s.issuerProfile.Version)]

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal initiate oidc4vci req: %w", err)
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

	var r *initiateOIDC4VCIResponse

	if err = json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("unmarshal initiate oidc4vci resp: %w", err)
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

func (s *Steps) runOIDC4VCIPreAuth(initiateOIDC4CIRequest initiateOIDC4VCIRequest, options ...oidc4vci.Opt) error {
	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(initiateOIDC4CIRequest)
	if err != nil {
		return fmt.Errorf("init credential issuance: %w", err)
	}

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypePreAuthorizedCode),
		oidc4vci.WithCredentialOffer(initiateOIDC4CIResponseData.OfferCredentialURL),
		oidc4vci.WithPin(*initiateOIDC4CIResponseData.UserPin),
	}

	opts = append(opts, options...)

	credentialTypes := strings.Split(s.issuedCredentialType, ",")

	// Set option filters
	for _, credentialType := range credentialTypes {
		format := s.getIssuerOIDCCredentialFormat(credentialType)
		opts = append(opts, oidc4vci.WithCredentialFilter(credentialType, format))
	}

	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init pre-auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run pre-auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIPreAuthWithInvalidClaims() error {
	initiateIssuanceRequest := initiateOIDC4VCIRequest{
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
		GrantType:       preAuthorizedCodeGrantType,
		UserPinRequired: true,
	}

	err := s.runOIDC4VCIPreAuth(initiateIssuanceRequest)
	if err == nil {
		return errors.New("error expected")
	}

	if !strings.Contains(err.Error(), "JSON-LD doc has different structure after compaction") {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (s *Steps) initiateCredentialIssuanceWithClaimsSchemaValidationError() error {
	initiateIssuanceRequest := initiateOIDC4VCIRequest{
		CredentialTemplateId: "universityDegreeTemplateID",
		ClaimData: &map[string]interface{}{
			"degree": map[string]string{
				"degree": "MIT",
			},
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
		},
		GrantType:       preAuthorizedCodeGrantType,
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

	initiateIssuanceRequest := initiateOIDC4VCIRequest{
		CredentialTemplateId: s.issuedCredentialTemplateID,
		ClaimData:            &claims,
		UserPinRequired:      true,
		GrantType:            preAuthorizedCodeGrantType,
	}

	return s.runOIDC4VCIPreAuth(initiateIssuanceRequest)
}

func (s *Steps) setProofType(proofType string) {
	s.proofType = proofType
}

func (s *Steps) runOIDC4CIPreAuthWithClientAttestation() error {
	claims, err := s.fetchClaimData(s.issuedCredentialType)
	if err != nil {
		return fmt.Errorf("fetchClaimData: %w", err)
	}

	req := initiateOIDC4VCIRequest{
		CredentialTemplateId: s.issuedCredentialTemplateID,
		ClaimData:            &claims,
		UserPinRequired:      true,
		GrantType:            preAuthorizedCodeGrantType,
	}

	initiateOIDC4CIResponseData, err := s.initiateCredentialIssuance(req)
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypePreAuthorizedCode),
		oidc4vci.WithCredentialOffer(initiateOIDC4CIResponseData.OfferCredentialURL),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithPin(*initiateOIDC4CIResponseData.UserPin),
	}
	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init pre-auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run pre-auth flow: %w", err)
	}

	return nil
}

func (s *Steps) addProofBuilder(opt []oidc4vci.Opt) []oidc4vci.Opt {
	switch s.proofType {
	case "cwt":
		return append(opt, oidc4vci.WithProofBuilder(oidc4vci.NewCWTProofBuilder()))
	case "ldp_vc":
		return append(opt, oidc4vci.WithProofBuilder(oidc4vci.NewLDPProofBuilder()))
	default:
		return opt
	}
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
	resp, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequestAuthFlow())
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithClientID(updatedClientID),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err == nil {
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
			return fmt.Errorf("unexpected ErrorField: %s", rfcError.ErrorField)
		}

	default:
		return fmt.Errorf("unexpected err: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthWithErrorInvalidSigningKeyID(errorContains string) error {
	builder := oidc4vci.NewJWTProofBuilder().
		WithCustomProofFn(func(
			ctx context.Context,
			req *oidc4vci.CreateProofRequest,
		) (string, error) {
			req.CustomHeaders[jose.HeaderKeyID] = "invalid-key-id"

			signedJWT, jwtErr := jwt.NewJoseSigned(req.Claims, req.CustomHeaders, req.Signer)
			if jwtErr != nil {
				return "", fmt.Errorf("create signed jwt: %w", jwtErr)
			}

			jws, jwtErr := signedJWT.Serialize(false)
			if jwtErr != nil {
				return "", fmt.Errorf("serialize signed jwt: %w", jwtErr)
			}

			return jws, nil
		})

	return s.runOIDC4VCIAuthWithError(errorContains, oidc4vci.WithProofBuilder(builder))
}

func (s *Steps) runOIDC4VCIAuthWithErrorInvalidSignatureValue(errorContains string) error {
	builder := oidc4vci.NewJWTProofBuilder().
		WithCustomProofFn(func(
			ctx context.Context,
			req *oidc4vci.CreateProofRequest,
		) (string, error) {
			signedJWT, jwtErr := jwt.NewJoseSigned(req.Claims, req.CustomHeaders, req.Signer)
			if jwtErr != nil {
				return "", fmt.Errorf("create signed jwt: %w", jwtErr)
			}

			jws, jwtErr := signedJWT.Serialize(false)
			if jwtErr != nil {
				return "", fmt.Errorf("serialize signed jwt: %w", jwtErr)
			}

			parts := strings.Split(jws, ".")
			jws = strings.Join([]string{parts[0], parts[1], "invalid-signature"}, ".")

			return jws, nil
		})

	return s.runOIDC4VCIAuthWithError(errorContains, oidc4vci.WithProofBuilder(builder))
}

func (s *Steps) runOIDC4VCIAuthWithErrorInvalidNonce(errorContains string) error {
	builder := oidc4vci.NewJWTProofBuilder().
		WithCustomProofFn(func(
			ctx context.Context,
			req *oidc4vci.CreateProofRequest,
		) (string, error) {
			req.Claims.Nonce = "invalid-nonce"

			signedJWT, jwtErr := jwt.NewJoseSigned(req.Claims, req.CustomHeaders, req.Signer)
			if jwtErr != nil {
				return "", fmt.Errorf("create signed jwt: %w", jwtErr)
			}

			jws, jwtErr := signedJWT.Serialize(false)
			if jwtErr != nil {
				return "", fmt.Errorf("serialize signed jwt: %w", jwtErr)
			}

			return jws, nil
		})

	return s.runOIDC4VCIAuthWithError(errorContains, oidc4vci.WithProofBuilder(builder))
}

func (s *Steps) runOIDC4VCIAuthWithError(errorContains string, overrideOpts ...oidc4vci.Opt) error {
	resp, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequestAuthFlow())
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}
	opts = s.addProofBuilder(opts)
	opts = append(opts, overrideOpts...)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider, opts...)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err == nil {
		return fmt.Errorf("error expected, got nil")
	}

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected err: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuth() error {
	resp, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequestAuthFlow())
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}
	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthBunchByCredentialConfigurationID(credentialConfigurationIDRaw string) error {
	initiateRequest, err := s.getInitiateAuthIssuanceRequestOfAllSupportedCredentials()
	if err != nil {
		return fmt.Errorf("getInitiateAuthIssuanceRequestOfAllSupportedCredentials: %w", err)
	}

	resp, err := s.initiateCredentialIssuance(*initiateRequest)
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	credentialConfigurationIDs := strings.Split(credentialConfigurationIDRaw, ",")

	opts := []oidc4vci.Opt{
		oidc4vci.WithBatchCredentialIssuance(),
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithCredentialConfigurationIDs(credentialConfigurationIDs),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}

	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthBunch() error {
	initiateRequest, err := s.getInitiateAuthIssuanceRequestOfAllSupportedCredentials()
	if err != nil {
		return fmt.Errorf("getInitiateAuthIssuanceRequestOfAllSupportedCredentials: %w", err)
	}

	resp, err := s.initiateCredentialIssuance(*initiateRequest)
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	credentialTypes := strings.Split(s.issuedCredentialType, ",")

	opts := []oidc4vci.Opt{
		oidc4vci.WithBatchCredentialIssuance(),
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
	}

	// Set option filters
	for _, credentialType := range credentialTypes {
		format := s.getIssuerOIDCCredentialFormat(credentialType)
		opts = append(opts, oidc4vci.WithCredentialFilter(credentialType, format))
	}

	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthBunchWithScopes(scopes string) error {
	initiateRequest, err := s.getInitiateAuthIssuanceRequestOfAllSupportedCredentials()
	if err != nil {
		return fmt.Errorf("getInitiateAuthIssuanceRequestOfAllSupportedCredentials: %w", err)
	}

	resp, err := s.initiateCredentialIssuance(*initiateRequest)
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	authRequestScopes := strings.Split(scopes, ",")

	opts := []oidc4vci.Opt{
		oidc4vci.WithBatchCredentialIssuance(),
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes(authRequestScopes),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
	}

	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIPreAuthBunch() error {
	initiateRequest, err := s.getInitiatePreAuthIssuanceRequestOfAllSupportedCredentials()
	if err != nil {
		return fmt.Errorf("getInitiatePreAuthIssuanceRequestOfAllSupportedCredentials: %w", err)
	}

	return s.runOIDC4VCIPreAuth(*initiateRequest, oidc4vci.WithBatchCredentialIssuance())
}

// getInitiateAuthIssuanceRequestOfAllSupportedCredentials returns Initiate issuance request body
// for all supported credential types by given Issuer.
// Returned structure contains CredentialConfiguration field, that is aimed for batch credentials issuance.
// Although, API supports format returned by getInitiateIssuanceRequestAuthFlow func.
func (s *Steps) getInitiateAuthIssuanceRequestOfAllSupportedCredentials() (*initiateOIDC4VCIRequest, error) {
	initiateRequest := &initiateOIDC4VCIRequest{
		GrantType:               authorizedCodeGrantType,
		OpState:                 uuid.New().String(),
		ResponseType:            "code",
		Scope:                   []string{"openid", "profile"},
		UserPinRequired:         false,
		CredentialConfiguration: map[string]InitiateIssuanceCredentialConfiguration{},
	}

	profileCredentialConf := s.issuerProfile.CredentialMetaData.CredentialsConfigurationSupported
	for credentialConfigurationID, credentialConf := range profileCredentialConf {
		credentialType := credentialConf.CredentialDefinition.Type[1]

		credentialTemplate, ok := lo.Find(s.issuerProfile.CredentialTemplates, func(item *profileapi.CredentialTemplate) bool {
			return item.Type == credentialType
		})

		if !ok {
			return nil, fmt.Errorf("unable to find credential template with type %s", credentialTemplate)
		}

		initiateRequest.CredentialConfiguration[credentialConfigurationID] = InitiateIssuanceCredentialConfiguration{
			ClaimEndpoint:        claimDataURL + "?credentialType=" + credentialType,
			CredentialTemplateId: credentialTemplate.ID,
		}

		initiateRequest.Scope = append(initiateRequest.Scope, credentialConf.Scope)
	}

	return initiateRequest, nil
}

// getInitiatePreAuthIssuanceRequestOfAllSupportedCredentials returns Pre Auth Initiate issuance request body
// for all supported credential types by given Issuer.
// Returned structure contains CredentialConfiguration field, that is aimed for batch credentials issuance.
func (s *Steps) getInitiatePreAuthIssuanceRequestOfAllSupportedCredentials() (*initiateOIDC4VCIRequest, error) {
	initiateRequest := &initiateOIDC4VCIRequest{
		GrantType:               preAuthorizedCodeGrantType,
		OpState:                 uuid.New().String(),
		ResponseType:            "code",
		Scope:                   []string{"openid", "profile"},
		UserPinRequired:         true,
		CredentialConfiguration: map[string]InitiateIssuanceCredentialConfiguration{},
	}

	profileCredentialConf := s.issuerProfile.CredentialMetaData.CredentialsConfigurationSupported
	for credentialConfigurationID, credentialConf := range profileCredentialConf {
		credentialType := credentialConf.CredentialDefinition.Type[1]

		credentialTemplate, ok := lo.Find(s.issuerProfile.CredentialTemplates, func(item *profileapi.CredentialTemplate) bool {
			return item.Type == credentialType
		})

		if !ok {
			return nil, fmt.Errorf("unable to find credential template with type %s", credentialTemplate)
		}

		claims, err := s.fetchClaimData(credentialType)
		if err != nil {
			return nil, fmt.Errorf("fetchClaimData: %w", err)
		}

		initiateRequest.CredentialConfiguration[credentialConfigurationID] = InitiateIssuanceCredentialConfiguration{
			ClaimData:            claims,
			CredentialTemplateId: credentialTemplate.ID,
		}

		initiateRequest.Scope = append(initiateRequest.Scope, credentialConf.Scope)
	}

	return initiateRequest, nil
}

func (s *Steps) runOIDC4VCIAuthWithCredentialConfigurationID(credentialConfigurationIDRaw string) error {
	resp, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequestAuthFlow())
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	credentialConfigurationIDs := strings.Split(credentialConfigurationIDRaw, ",")

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		// Do not define oidc4vci.WithCredentialFilter() explicitly.
		// As a result - authorization_details object for Authorize request will be based on credentialConfigurationIDs.
		// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.1-2.2
		oidc4vci.WithCredentialConfigurationIDs(credentialConfigurationIDs),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}
	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthWithScopes(scopes string) error {
	scopesList := strings.Split(scopes, ",")

	initiateIssuanceRequest := initiateOIDC4VCIRequest{
		ClaimEndpoint:        claimDataURL + "?credentialType=" + s.issuedCredentialType,
		CredentialTemplateId: s.issuedCredentialTemplateID,
		GrantType:            "authorization_code",
		OpState:              uuid.New().String(),
		ResponseType:         "code",
		Scope:                append([]string{"openid", "profile"}, scopesList...),
		UserPinRequired:      false,
	}

	resp, err := s.initiateCredentialIssuance(initiateIssuanceRequest)
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		// Do not define oidc4vci.WithCredentialFilter() nor oidc4vci.WithCredentialConfigurationIDs() explicitly.
		// As a result - authorization_details object for Authorize request will be based on scopes.
		// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.2
		oidc4vci.WithScopes(scopesList),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}
	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthWalletInitiatedFlow() error {
	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypeWalletInitiated),
		oidc4vci.WithIssuerState(fmt.Sprintf(vcsIssuerURL, s.issuerProfile.ID, s.issuerProfile.Version)),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}
	opts = s.addProofBuilder(opts)

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("init wallet-initiated auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run wallet-initiated auth flow: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4VCIAuthWithInvalidClaims() error {
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

	issuanceReq := s.getInitiateIssuanceRequestAuthFlow()
	issuanceReq.ClaimEndpoint += fmt.Sprintf("&claim_data=%s", base64.URLEncoding.EncodeToString(claimsDataBytes))

	resp, err := s.initiateCredentialIssuance(issuanceReq)
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider,
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithClientID("oidc4vc_client"),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err == nil {
		return fmt.Errorf("error expected, got nil")
	}

	if !strings.Contains(err.Error(), "validation error: [(root): name is required; degree: type is required]") {
		return fmt.Errorf("unexpected error: %w", err)
	}

	return nil
}

func (s *Steps) runOIDC4CIAuthWithClientRegistrationMethod(method string) error {
	resp, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequestAuthFlow())
	if err != nil {
		return fmt.Errorf("initiate credential issuance: %w", err)
	}

	opts := []oidc4vci.Opt{
		oidc4vci.WithFlowType(oidc4vci.FlowTypeAuthorizationCode),
		oidc4vci.WithCredentialOffer(resp.OfferCredentialURL),
		oidc4vci.WithCredentialFilter(s.issuedCredentialType, s.getIssuerOIDCCredentialFormat(s.issuedCredentialType)),
		oidc4vci.WithScopes([]string{"openid", "profile"}),
		oidc4vci.WithRedirectURI("http://127.0.0.1/callback"),
		oidc4vci.WithUserLogin("bdd-test"),
		oidc4vci.WithUserPassword("bdd-test-pass"),
	}
	opts = s.addProofBuilder(opts)

	switch method {
	case "pre-registered":
		opts = append(opts, oidc4vci.WithClientID("oidc4vc_client"))
	case "dynamic":
		clientID, regErr := s.registerOAuthClient(resp.OfferCredentialURL)
		if regErr != nil {
			return fmt.Errorf("register oauth client: %w", err)
		}

		opts = append(opts, oidc4vci.WithClientID(clientID))
	case "discoverable":
		opts = append(opts, oidc4vci.WithClientID("https://file-server.trustbloc.local:10096"))
		opts = append(opts, oidc4vci.WithEnableDiscoverableClientID())
	default:
		return fmt.Errorf("unsupported client registration method: %s", method)
	}

	flow, err := oidc4vci.NewFlow(s.oidc4vciProvider, opts...)
	if err != nil {
		return fmt.Errorf("init auth flow: %w", err)
	}

	if _, err = flow.Run(context.Background()); err != nil {
		return fmt.Errorf("run auth flow: %w", err)
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

	openIDConfig, err := s.wellKnownService.GetWellKnownOpenIDConfiguration(offer.CredentialIssuer)
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

func (s *Steps) getInitiateIssuanceRequestAuthFlow() initiateOIDC4VCIRequest {
	return initiateOIDC4VCIRequest{
		ClaimEndpoint:        claimDataURL + "?credentialType=" + s.issuedCredentialType,
		CredentialTemplateId: s.issuedCredentialTemplateID,
		GrantType:            authorizedCodeGrantType,
		OpState:              uuid.New().String(),
		ResponseType:         "code",
		Scope:                []string{"openid", "profile"},
		UserPinRequired:      false,
	}
}

func getOrgAuthTokenKey(org string) string {
	return org + "-accessToken"
}

func (s *Steps) checkIssuedCredential(expectedCredentialsAmount string) error {
	credentialMap, err := s.wallet.GetAll()
	if err != nil {
		return fmt.Errorf("wallet.GetAll(): %w", err)
	}

	amount, _ := strconv.Atoi(expectedCredentialsAmount)
	if len(credentialMap) != amount {
		return fmt.Errorf(
			"unexpected amount of credentials issued. Expected %d, got %d", amount, len(credentialMap))
	}

	var vcParsed *verifiable.Credential

	for _, vcBytes := range credentialMap {
		vcParsed, err = verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(s.documentLoader))
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
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
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
		if err := s.wallet.Add(cred); err != nil {
			return fmt.Errorf("add credential to wallet: %w", err)
		}
	}

	return nil
}

func (s *Steps) saveCredentialsInWallet() error {
	for _, cred := range s.bddContext.CreatedCredentialsSet {
		if err := s.wallet.Add(cred); err != nil {
			return fmt.Errorf("add credential to wallet: %w", err)
		}
	}

	return nil
}

func (s *Steps) initiateCredentialIssuanceWithError(errorContains string) error {
	_, err := s.initiateCredentialIssuance(s.getInitiateIssuanceRequestAuthFlow())

	if !strings.Contains(err.Error(), errorContains) {
		return fmt.Errorf("unexpected error on initiateCredentialIssuance: %w", err)
	}

	return nil
}

func (s *Steps) getIssuerOIDCCredentialFormat(credentialType string) vcsverifiable.OIDCFormat {
	for _, credentialConf := range s.issuerProfile.CredentialMetaData.CredentialsConfigurationSupported {
		if credentialConf.CredentialDefinition == nil {
			continue
		}

		if lo.Contains(credentialConf.CredentialDefinition.Type, credentialType) {
			return credentialConf.Format
		}
	}

	return ""
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

type oidc4vciProvider struct {
	storageProvider    storageapi.Provider
	httpClient         *http.Client
	documentLoader     ld.DocumentLoader
	vdrRegistry        vdrapi.Registry
	cryptoSuite        api.Suite
	attestationService *attestation.Service
	trustRegistry      *trustregistry.Client
	wallet             *wallet.Wallet
	wellKnownService   *wellknown.Service
}

func (p *oidc4vciProvider) StorageProvider() storageapi.Provider {
	return p.storageProvider
}

func (p *oidc4vciProvider) HTTPClient() *http.Client {
	return p.httpClient
}

func (p *oidc4vciProvider) DocumentLoader() ld.DocumentLoader {
	return p.documentLoader
}

func (p *oidc4vciProvider) VDRegistry() vdrapi.Registry {
	return p.vdrRegistry
}

func (p *oidc4vciProvider) CryptoSuite() api.Suite {
	return p.cryptoSuite
}

func (p *oidc4vciProvider) AttestationService() oidc4vci.AttestationService {
	return p.attestationService
}

func (p *oidc4vciProvider) TrustRegistry() oidc4vci.TrustRegistry {
	return p.trustRegistry
}

func (p *oidc4vciProvider) Wallet() *wallet.Wallet {
	return p.wallet
}

func (p *oidc4vciProvider) WellKnownService() *wellknown.Service {
	return p.wellKnownService
}
