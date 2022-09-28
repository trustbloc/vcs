/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4vc"
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

func TestAuthorizeRequest(t *testing.T) {
	srv := testServer(t)
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
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge_method", "S256"),
					oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
				}
				authCodeURL = newOAuth2Client(srv.URL).AuthCodeURL(nonce(), params...)
			},
			statusCode: http.StatusOK,
		},
		{
			name: "invalid client",
			setup: func() {
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge", ""),
				}

				authCodeURL = newOAuth2Client(srv.URL, withClientID("invalid-client")).AuthCodeURL(nonce(), params...)
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "missing code challenge",
			setup: func() {
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge", ""),
				}

				authCodeURL = newOAuth2Client(srv.URL).AuthCodeURL(nonce(), params...)
			},
			statusCode: http.StatusNotAcceptable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			resp, err := http.Get(authCodeURL)
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
			name: "success",
			setup: func() {
				params := []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("code_challenge_method", "S256"),
					oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
				}

				authCodeURL := newOAuth2Client(srv.URL).AuthCodeURL(nonce(), params...)

				resp, err := http.Get(authCodeURL)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)

				authCode = resp.Request.URL.Query().Get("code")
			},
			statusCode: http.StatusOK,
		},
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

func TestPushedAuthorizedRequest(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	var oauthClient *oauth2.Config

	tests := []struct {
		name       string
		setup      func()
		statusCode int
	}{
		{
			name: "success",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL)
			},
			statusCode: http.StatusCreated,
		},
		{
			name: "invalid client",
			setup: func() {
				oauthClient = newOAuth2Client(srv.URL, withClientID("invalid-client"))
			},
			statusCode: http.StatusUnauthorized,
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

			// pushed authorization request
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

func TestAuthorizeCodeGrantFlow(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	oauthClient := newOAuth2Client(srv.URL)

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
	}

	authCodeURL := oauthClient.AuthCodeURL(nonce(), params...)

	// get authorization code
	resp, err := http.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// exchange authorization code for access token
	resp, err = http.PostForm(srv.URL+"/oidc/token", url.Values{
		"code":          {resp.Request.URL.Query().Get("code")},
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

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	token := oauth2.Token{}
	require.NoError(t, json.Unmarshal(body, &token))
	require.NotEmpty(t, token.AccessToken)
}

func TestAuthorizeCodeGrantFlowWithPAR(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	oauthClient := newOAuth2Client(srv.URL)

	query := url.Values{}
	query.Set("client_id", oauthClient.ClientID)
	query.Set("client_secret", oauthClient.ClientSecret)
	query.Set("response_type", "code")
	query.Set("state", nonce())
	query.Set("scope", strings.Join(oauthClient.Scopes, " "))
	query.Set("redirect_uri", oauthClient.RedirectURL)

	// pushed authorization request
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

	authCodeURL := srv.URL + "/oidc/authorize?" + query.Encode()

	resp, err = http.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// TODO: exchange authorization code for access token using oauthClient.Exchange() method
}

func testServer(t *testing.T) *httptest.Server {
	t.Helper()

	e := echo.New()

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

	controller, err := oidc4vc.NewController(&oidc4vc.Config{OAuth2Provider: oauth2Provider})
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

// options to customize OAuth2 client.
type options struct {
	clientID string
}

// Opt configures OAuth2 client options.
type Opt func(*options)

func withClientID(clientID string) Opt {
	return func(o *options) {
		o.clientID = clientID
	}
}

func newOAuth2Client(serverURL string, opts ...Opt) *oauth2.Config {
	op := &options{
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
