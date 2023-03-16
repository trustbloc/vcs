/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	"github.com/trustbloc/vcs/pkg/restapi/handlers"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	oidc4cisvc "github.com/trustbloc/vcs/pkg/service/oidc4ci"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4cistatestore"
)

const (
	clientID = "test-client"
)

func TestAuthorizeCodeGrantFlow(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = resterr.HTTPErrorHandler(trace.NewNoopTracerProvider().Tracer(""))

	opState := "QIn85XAEHwlPyCVRhTww"

	srv := httptest.NewServer(e)
	defer srv.Close()

	fositeStore := getDefaultStore()
	fositeStore.Clients[clientID] = &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
		RedirectURIs:  []string{"/client/cb"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
	}

	// prepend client redirect URIs with test server URL
	for _, client := range fositeStore.Clients {
		c, ok := client.(*fosite.DefaultClient)
		if ok {
			c.RedirectURIs[0] = srv.URL + c.RedirectURIs[0]
		}
	}

	config := new(fosite.Config)
	config.EnforcePKCE = true

	var hmacStrategy = &fositeoauth.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			Config: &fosite.Config{
				GlobalSecret: []byte("secret-for-signing-and-verifying-signatures"),
			},
		},
		Config: &fosite.Config{
			AuthorizeCodeLifespan: time.Minute,
			AccessTokenLifespan:   time.Hour,
		},
	}

	oauth2Provider := compose.Compose(config, fositeStore, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	oauth2Client := NewMockOAuth2Client(gomock.NewController(t))
	oauth2Client.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			_ context.Context,
			cfg oauth2.Config,
			state string,
			opts ...oauth2client.AuthCodeOption,
		) string {
			return (&cfg).AuthCodeURL(state)
		})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	v, err := jwt.NewEd25519Verifier(pub)
	require.NoError(t, err)

	verifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "EdDSA",
		Verifier: v,
	})

	controller := oidc4ci.NewController(&oidc4ci.Config{
		OAuth2Provider:          oauth2Provider,
		StateStore:              &memoryStateStore{kv: make(map[string]*oidc4cistatestore.AuthorizeState)},
		IssuerInteractionClient: mockIssuerInteractionClient(t, srv.URL, opState),
		IssuerVCSPublicHost:     srv.URL,
		OAuth2Client:            oauth2Client,
		JWTVerifier:             verifier,
		Tracer:                  trace.NewNoopTracerProvider().Tracer(""),
	})

	oidc4ci.RegisterHandlers(e, controller)

	registerThirdPartyOIDCAuthorizeEndpoint(t, e)
	registerClientCallback(t, e)

	oauthClient := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "foobar",
		RedirectURL:  srv.URL + "/client/cb",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			TokenURL:  srv.URL + "/oidc/token",
			AuthURL:   srv.URL + "/oidc/authorize",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("issuer_state", opState),
	}

	authCodeURL := oauthClient.AuthCodeURL(opState, params...)

	resp, err := http.DefaultClient.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	code := resp.Request.URL.Query().Get("code")
	require.NotEmpty(t, code)

	token, err := oauthClient.Exchange(context.TODO(), code,
		oauth2.SetAuthURLParam("code_verifier", "xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"),
	)

	require.NoError(t, err)
	require.NotNil(t, token)
	require.NotEmpty(t, token.AccessToken)
	require.NotEmpty(t, token.Extra("c_nonce"))
	require.NotEmpty(t, token.Extra("c_nonce_expires_in"))

	httpClient := oauthClient.Client(context.Background(), token)

	claims := &oidc4ci.JWTProofClaims{
		Issuer:   clientID,
		IssuedAt: time.Now().Unix(),
		Nonce:    token.Extra("c_nonce").(string),
	}

	signedJWT, err := jwt.NewSigned(claims, nil, jwt.NewEd25519Signer(priv))
	require.NoError(t, err)

	jws, err := signedJWT.Serialize(false)
	require.NoError(t, err)

	b, err := json.Marshal(oidc4ci.CredentialRequest{
		Format: lo.ToPtr(string(common.JwtVcJsonLd)),
		Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: jws},
		Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
	})
	require.NoError(t, err)

	resp, err = httpClient.Post(srv.URL+"/oidc/credential", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPreAuthorizeCodeGrantFlow(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = resterr.HTTPErrorHandler(trace.NewNoopTracerProvider().Tracer(""))

	srv := httptest.NewServer(e)
	defer srv.Close()

	fositeStore := getDefaultStore()
	fositeStore.Clients["oidc4vc_client"] = &fosite.DefaultClient{
		ID:            "oidc4vc_client",
		Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
		RedirectURIs:  []string{"http://127.0.0.1/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
	}

	config := new(fosite.Config)
	config.EnforcePKCE = true

	var hmacStrategy = &fositeoauth.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			Config: &fosite.Config{
				GlobalSecret: []byte("secret-for-signing-and-verifying-signatures"),
			},
		},
		Config: &fosite.Config{
			AuthorizeCodeLifespan: time.Minute,
			AccessTokenLifespan:   time.Hour,
		},
	}

	oauth2Provider := compose.Compose(config, fositeStore, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
		compose.OAuth2TokenIntrospectionFactory,
		handlers.OAuth2PreAuthorizeFactory,
	)

	interaction := NewMockIssuerInteractionClient(gomock.NewController(t))
	preAuthClient := NewMockHTTPClient(gomock.NewController(t))

	controller := oidc4ci.NewController(&oidc4ci.Config{
		OAuth2Provider:          oauth2Provider,
		StateStore:              &memoryStateStore{kv: make(map[string]*oidc4cistatestore.AuthorizeState)},
		IssuerInteractionClient: interaction,
		IssuerVCSPublicHost:     srv.URL,
		ExternalHostURL:         srv.URL,
		OAuth2Client:            oauth2client.NewOAuth2Client(),
		PreAuthorizeClient:      preAuthClient,
		DefaultHTTPClient:       http.DefaultClient,
		Tracer:                  trace.NewNoopTracerProvider().Tracer(""),
	})

	oidc4ci.RegisterHandlers(e, controller)

	code := "awesome-pre-auth-code"
	pin := "493536"

	interaction.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
		issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
			PreAuthorizedCode: code,
			UserPin:           lo.ToPtr(pin),
		},
	).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"scopes":["openid","profile"],"op_state":"QIn85XAEHwlPyCVRhTww", "tx_id" : "12345"}`)), //nolint:lll
	}, nil)

	resp, err := http.DefaultClient.PostForm(fmt.Sprintf("%v/oidc/token", srv.URL), url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
		"user_pin":            {pin},
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	var token oidc4ci.AccessTokenResponse
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&token))
	assert.Equal(t, "bearer", token.TokenType)
	assert.NotEmpty(t, token.AccessToken)
	assert.Greater(t, *token.ExpiresIn, 0)
}

func mockIssuerInteractionClient(
	t *testing.T,
	serverURL string,
	opState string,
) *MockIssuerInteractionClient {
	t.Helper()

	client := NewMockIssuerInteractionClient(gomock.NewController(t))

	client.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			ctx context.Context,
			req issuer.PrepareAuthorizationRequestJSONRequestBody,
			reqEditors ...issuer.RequestEditorFn,
		) (*http.Response, error) {
			b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
				AuthorizationEndpoint: serverURL + "/third-party/oidc/authorize",
				AuthorizationRequest: issuer.OAuthParameters{
					ClientId:     clientID,
					ClientSecret: "foobar",
					ResponseType: req.ResponseType,
					Scope:        lo.FromPtr(req.Scope),
				},
				PushedAuthorizationRequestEndpoint: nil,
			})
			if err != nil {
				return nil, err
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBuffer(b)),
			}, nil
		})

	client.EXPECT().StoreAuthorizationCodeRequest(gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			ctx context.Context,
			req issuer.StoreAuthorizationCodeRequestJSONRequestBody,
			reqEditors ...issuer.RequestEditorFn,
		) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBuffer(nil)),
			}, nil
		})

	client.EXPECT().ExchangeAuthorizationCodeRequest(
		gomock.Any(),
		issuer.ExchangeAuthorizationCodeRequestJSONRequestBody{
			OpState: opState,
		},
	).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(`{"tx_id":"txID"}`)),
	}, nil)

	b, err := json.Marshal(issuer.PrepareCredentialResult{
		Credential: "credential in jwt format",
		Format:     string(vcsverifiable.Jwt),
		Retry:      false,
	})
	require.NoError(t, err)

	client.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(b)),
	}, nil)

	return client
}

func getDefaultStore() *storage.MemoryStore {
	return &storage.MemoryStore{
		Clients:                map[string]fosite.Client{},
		AuthorizeCodes:         map[string]storage.StoreAuthorizeCode{},
		IDSessions:             make(map[string]fosite.Requester),
		AccessTokens:           map[string]fosite.Requester{},
		RefreshTokens:          map[string]storage.StoreRefreshToken{},
		PKCES:                  map[string]fosite.Requester{},
		Users:                  make(map[string]storage.MemoryUserRelation),
		AccessTokenRequestIDs:  map[string]string{},
		RefreshTokenRequestIDs: map[string]string{},
		IssuerPublicKeys:       map[string]storage.IssuerPublicKeys{},
		PARSessions:            map[string]fosite.AuthorizeRequester{},
	}
}

func registerThirdPartyOIDCAuthorizeEndpoint(t *testing.T, e *echo.Echo) {
	t.Helper()

	e.GET("/third-party/oidc/authorize", func(c echo.Context) error {
		req := c.Request()

		// TODO: Validate authorize request

		q := &url.Values{}
		q.Set("code", "foo")
		q.Set("state", req.URL.Query().Get("state"))

		redirectURI := req.URL.Query().Get("redirect_uri") + "?" + q.Encode()

		return c.Redirect(http.StatusSeeOther, redirectURI)
	})
}

func registerClientCallback(t *testing.T, e *echo.Echo) {
	t.Helper()

	e.GET("/client/cb", func(c echo.Context) error {
		req := c.Request()

		code := req.URL.Query().Get("code")
		require.Contains(t, code, "ory_ac_")

		return nil
	})
}

type memoryStateStore struct {
	kv map[string]*oidc4cistatestore.AuthorizeState
	mu sync.RWMutex
}

func (s *memoryStateStore) GetAuthorizeState(
	_ context.Context,
	opState string,
) (*oidc4cistatestore.AuthorizeState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.kv[opState]
	if !ok {
		return nil, fmt.Errorf("key %s not found", opState)
	}

	return v, nil
}

func (s *memoryStateStore) SaveAuthorizeState(
	_ context.Context,
	opState string,
	state *oidc4cistatestore.AuthorizeState,
	_ ...func(insertOptions *oidc4cisvc.InsertOptions),
) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.kv[opState] = state

	return nil
}
