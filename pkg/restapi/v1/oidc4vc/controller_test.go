/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4vc"
	oidc4vcapi "github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

const (
	testClientID = "test-client"
	nonceLength  = 15
)

//nolint:gochecknoglobals
var store = &storage.MemoryStore{
	Clients: map[string]fosite.Client{
		testClientID: &fosite.DefaultClient{
			ID:            testClientID,
			Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs:  []string{"/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid"},
		},
	},
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

func TestPushedAuthorizedRequest(t *testing.T) {
	mockOIDC4VCService := NewMockOIDC4VCService(gomock.NewController(t))

	srv := testServer(t, withOIDC4VCService(mockOIDC4VCService))
	defer srv.Close()

	var (
		oauthClient *oauth2.Config
		ad          string
	)

	tests := []struct {
		name       string
		setup      func()
		statusCode int
	}{
		{
			name: "success",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL)

				mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc4vcapi.TxID("txID"), nil)

				ad = `{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"ldp_vc","locations":[]}` //nolint:lll
			},
			statusCode: http.StatusCreated,
		},
		{
			name: "service error",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL)

				mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc4vcapi.TxID(""), errors.New("service error"))
			},
			statusCode: http.StatusInternalServerError,
		},
		{
			name: "invalid client",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL, withClientID("invalid-client"))
				mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				ad = `{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","locations":[]}` //nolint:lll
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "fail to unmarshal authorization_details",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL)
				mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				ad = "invalid json"
			},
			statusCode: http.StatusInternalServerError,
		},
		{
			name: "invalid authorization_details.type",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL)
				mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				ad = `{"type":"invalid","credential_type":"https://did.example.org/healthCard","locations":[]}`
			},
			statusCode: http.StatusInternalServerError,
		},
		{
			name: "invalid authorization_details.format",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL)
				mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
				ad = `{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","format":"invalid","locations":[]}` //nolint:lll
			},
			statusCode: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			query := url.Values{}
			query.Set("client_id", oauthClient.ClientID)
			query.Set("client_secret", oauthClient.ClientSecret)
			query.Set("response_type", "code")
			query.Set("state", nonce())
			query.Set("scope", strings.Join(oauthClient.Scopes, " "))
			query.Set("redirect_uri", oauthClient.RedirectURL)
			query.Set("authorization_details", ad)

			req, err := http.NewRequest(http.MethodPost, srv.URL+"/oidc/par", strings.NewReader(query.Encode()))
			require.NoError(t, err)

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			defer func() {
				if closeErr := resp.Body.Close(); closeErr != nil {
					t.Logf("Failed to close response body: %s", closeErr)
				}
			}()

			require.Equal(t, tt.statusCode, resp.StatusCode)
		})
	}
}

func TestAuthorizeRequest(t *testing.T) {
	oidcService := NewMockOIDC4VCService(gomock.NewController(t))

	srv := testServer(t, withOIDC4VCService(oidcService))
	defer srv.Close()

	var authCodeURL string

	tests := []struct {
		name       string
		setup      func()
		statusCode int
	}{
		{
			name: "success",
			setup: func() {
				opState := uuid.NewString()
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge_method", "S256"),
					oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
					oauth2.SetAuthURLParam("op_state", opState),
				}
				authCodeURL = newOAuth2Client(srv.URL).AuthCodeURL(nonce(), params...)
				oidcService.EXPECT().HandleAuthorize(gomock.Any(), opState, gomock.Any()).
					Return("http://redirect", nil)
			},
			statusCode: http.StatusSeeOther,
		},
		{
			name: "invalid client",
			setup: func() {
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge", ""),
					oauth2.SetAuthURLParam("op_state", uuid.NewString()),
				}

				authCodeURL = newOAuth2Client(srv.URL, withClientID("invalid-client")).AuthCodeURL(nonce(), params...)
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "missing op state",
			setup: func() {
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge", ""),
				}

				authCodeURL = newOAuth2Client(srv.URL).AuthCodeURL(nonce(), params...)
			},
			statusCode: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			cl := http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			resp, err := cl.Get(authCodeURL)
			require.NoError(t, err)
			require.Equal(t, tt.statusCode, resp.StatusCode)
		})
	}
}

func TestTokenRequest(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	var authCode string

	tests := []struct {
		name       string
		setup      func()
		statusCode int
	}{
		{
			name: "invalid authorization code",
			setup: func() {
				authCode = "invalid-code"
			},
			statusCode: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			resp, err := http.PostForm(srv.URL+"/oidc/token", url.Values{
				"code":          {authCode},
				"grant_type":    {"authorization_code"},
				"client_id":     {testClientID},
				"client_secret": {"foobar"},
				"redirect_uri":  {srv.URL + "/callback"},
				"code_verifier": {"xalsLDydJtHwIQZukUyj6boam5vMUaJRWv-BnGCAzcZi3ZTs"},
			})
			require.NoError(t, err)

			defer func() {
				if closeErr := resp.Body.Close(); closeErr != nil {
					t.Logf("Failed to close response body: %s", closeErr)
				}
			}()

			require.Equal(t, tt.statusCode, resp.StatusCode)
		})
	}
}

func TestAuthorizeCodeGrantFlow(t *testing.T) {
	mockOIDC4VCService := NewMockOIDC4VCService(gomock.NewController(t))
	mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	opState := uuid.NewString()

	redirectURL := fmt.Sprintf("https://trust/redirect?id=%v", uuid.NewString())

	mockOIDC4VCService.EXPECT().HandleAuthorize(gomock.Any(), opState, gomock.Any()).
		DoAndReturn(func(
			ctx context.Context,
			opState string,
			responder oidc4vcapi.InternalAuthorizationResponder,
		) (string, error) {
			assert.Equal(t, fosite.ResponseModeType("query"), responder.RespondMode)

			assert.Empty(t, responder.AuthorizeResponse.Header)
			assert.Len(t, responder.AuthorizeResponse.Parameters, 3)
			assert.NotEmpty(t, responder.AuthorizeResponse.Parameters["code"])
			assert.NotEmpty(t, responder.AuthorizeResponse.Parameters["state"])
			assert.Equal(t, []string{""}, responder.AuthorizeResponse.Parameters["scope"])

			assert.NotNil(t, responder.RedirectURI)
			assert.Equal(t, "/callback", responder.RedirectURI.Path)

			return redirectURL, nil
		})
	srv := testServer(t, withOIDC4VCService(mockOIDC4VCService))
	defer srv.Close()

	oauthClient := newOAuth2Client(srv.URL)

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("op_state", opState),
	}

	authCodeURL := oauthClient.AuthCodeURL(nonce(), params...)

	cl := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// get authorization code
	resp, err := cl.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, redirectURL, resp.Header.Get("location"))
}

func TestAuthorizeCodeGrantFlowWithPAR(t *testing.T) {
	opState := uuid.NewString()
	randURI := fmt.Sprintf("https://external-oidc-provider.com/%v", opState)

	mockOIDC4VCService := NewMockOIDC4VCService(gomock.NewController(t))
	mockOIDC4VCService.EXPECT().HandlePAR(gomock.Any(), gomock.Any(), gomock.Any()).Return(oidc4vcapi.TxID("txID"), nil)

	srv := testServer(t, withOIDC4VCService(mockOIDC4VCService))
	defer srv.Close()

	mockOIDC4VCService.EXPECT().HandleAuthorize(gomock.Any(), opState, gomock.Any()).Return(randURI, nil)

	oauthClient := newOAuth2Client(srv.URL)

	query := url.Values{}
	query.Set("client_id", oauthClient.ClientID)
	query.Set("client_secret", oauthClient.ClientSecret)
	query.Set("response_type", "code")
	query.Set("state", nonce())
	query.Set("scope", strings.Join(oauthClient.Scopes, " "))
	query.Set("redirect_uri", oauthClient.RedirectURL)
	query.Set("authorization_details", `{"type":"openid_credential","credential_type":"https://did.example.org/healthCard","locations":[]}`) //nolint:lll

	// pushed authorization request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/oidc/par",
		strings.NewReader(query.Encode()))
	require.NoError(t, err)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Logf("Failed to close response body: %s", closeErr)
		}
	}()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	m := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(body, &m))

	requestURI, _ := m["request_uri"].(string)
	require.NotEmpty(t, requestURI)

	// get authorization code
	query = url.Values{}
	query.Set("request_uri", requestURI)
	query.Set("client_id", oauthClient.ClientID)
	query.Set("response_type", "code")
	query.Set("code_challenge_method", "S256")
	query.Set("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8")
	query.Set("code", nonce())
	query.Set("op_state", opState)

	authCodeURL := srv.URL + "/oidc/authorize?" + query.Encode()

	cl := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err = cl.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, randURI, resp.Header.Get("location"))
}

type oidc4VCService interface {
	HandlePAR(ctx context.Context, opState string, ad *oidc4vcapi.AuthorizationDetails) (oidc4vcapi.TxID, error)
	HandleAuthorize(
		ctx context.Context,
		opState string,
		responder oidc4vcapi.InternalAuthorizationResponder,
	) (string, error)
}

// serverOptions to customize test server.
type serverOptions struct {
	oidc4VCService oidc4VCService
}

// ServerOpt configures test server options.
type ServerOpt func(options *serverOptions)

func withOIDC4VCService(svc oidc4VCService) ServerOpt {
	return func(o *serverOptions) {
		o.oidc4VCService = svc
	}
}

func testServer(t *testing.T, opts ...ServerOpt) *httptest.Server {
	t.Helper()

	op := &serverOptions{}

	for _, fn := range opts {
		fn(op)
	}

	e := echo.New()
	e.HTTPErrorHandler = resterr.HTTPErrorHandler

	config := new(fosite.Config)
	config.EnforcePKCE = true

	var hmacStrategy = &fositeoauth2.HMACSHAStrategy{
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

	oauth2Provider := compose.Compose(config, store, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
	)

	controller, err := oidc4vc.NewController(&oidc4vc.Config{
		OAuth2Provider: oauth2Provider,
		OIDC4VCService: op.oidc4VCService,
	})
	require.NoError(t, err)

	oidc4vc.RegisterHandlers(e, controller)

	// TODO: Add callback/redirect handler in production code
	e.GET("/callback", func(c echo.Context) error {
		q := c.Request().URL.Query()

		if q.Get("code") == "" && q.Get("error") == "" {
			require.NotEmpty(t, q.Get("code"))
			require.NotEmpty(t, q.Get("error"))
		}

		if q.Get("code") != "" {
			if _, err = c.Response().Write([]byte("code: ok")); err != nil {
				t.Logf("Failed to write response: %s", err)
			}
		}

		if q.Get("error") != "" {
			c.Response().WriteHeader(http.StatusNotAcceptable)
			if _, err = c.Response().Write([]byte("error: " + q.Get("error"))); err != nil {
				t.Logf("Failed to write response: %s", err)
			}
		}

		return nil
	})

	srv := httptest.NewServer(e)

	for _, client := range store.Clients {
		c, ok := client.(*fosite.DefaultClient)
		if ok {
			c.RedirectURIs[0] = srv.URL + "/callback"
		}
	}

	return srv
}

// clientOptions to customize OAuth2 client.
type clientOptions struct {
	clientID string
}

// ClientOpt configures OAuth2 client options.
type ClientOpt func(*clientOptions)

func withClientID(clientID string) ClientOpt {
	return func(o *clientOptions) {
		o.clientID = clientID
	}
}

func newOAuth2Client(serverURL string, opts ...ClientOpt) *oauth2.Config {
	op := &clientOptions{
		clientID: testClientID,
	}

	for _, fn := range opts {
		fn(op)
	}

	return &oauth2.Config{
		ClientID:     op.clientID,
		ClientSecret: "foobar",
		RedirectURL:  serverURL + "/callback",
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			TokenURL:  serverURL + "/oidc/token",
			AuthURL:   serverURL + "/oidc/authorize",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func nonce() string {
	b := make([]byte, nonceLength)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}
