/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:unused
package oidc4vc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	fositeoauth "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4vc"
	oidc4vcsvc "github.com/trustbloc/vcs/pkg/service/oidc4vc"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/oidc4vcstatestore"
)

const (
	testClientID = "test-client"
	nonceLength  = 15
)

//nolint:gochecknoglobals
var fositeMemoryStore = &storage.MemoryStore{
	Clients: map[string]fosite.Client{
		testClientID: &fosite.DefaultClient{
			ID:            testClientID,
			Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs:  []string{"/redirect"},
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

func TestAuthorizeCodeGrantFlow(t *testing.T) {
	t.Skip() // TODO: Update as part of changes to BDD tests.

	mockClient := NewMockIssuerInteractionClient(gomock.NewController(t))
	mockStateStore := NewMockStateStore(gomock.NewController(t))

	opState := uuid.NewString()

	redirectURL := fmt.Sprintf("https://trust/redirect?id=%v", uuid.NewString())

	mockClient.EXPECT().PushAuthorizationDetails(gomock.Any(), gomock.Any()).Times(0)

	b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		AuthorizationRequest: issuer.OAuthParameters{
			ClientId:     "client_id",
			ClientSecret: "client_secret",
			ResponseType: "code",
			Scope:        []string{"openid"},
		},
		PushedAuthorizationRequestEndpoint: nil,
		TxId:                               "txID",
	})
	require.NoError(t, err)

	mockClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(b)),
	}, nil)

	mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), opState, gomock.Any(), gomock.Any()).
		DoAndReturn(func(
			ctx context.Context,
			opState string,
			state *oidc4vcstatestore.AuthorizeState,
			params ...func(insertOptions *oidc4vcsvc.InsertOptions),
		) error {
			assert.Equal(t, "query", state.RespondMode)

			assert.Empty(t, state.Header)
			assert.Len(t, state.Parameters, 3)
			assert.NotEmpty(t, state.Parameters["code"])
			assert.NotEmpty(t, state.Parameters["state"])
			assert.Equal(t, []string{""}, state.Parameters["scope"])

			assert.NotNil(t, state.RedirectURI)

			return nil
		})

	srv := testServer(t,
		withIssuerInteractionClient(mockClient),
		withStateStore(mockStateStore),
	)

	defer srv.Close()

	oauthClient := newOAuthClient(srv.URL)

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", "MLSjJIlPzeRQoN9YiIsSzziqEuBSmS4kDgI3NDjbfF8"),
		oauth2.SetAuthURLParam("op_state", opState),
	}

	authCodeURL := oauthClient.AuthCodeURL(nonce(t), params...)

	httpClient := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// get authorization code
	resp, err := httpClient.Get(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	require.Equal(t, redirectURL, resp.Header.Get("location"))
}

func TestAuthorizeCodeGrantFlowWithPAR(t *testing.T) {
	t.Skip() // TODO: Update as part of changes to BDD tests.

	opState := uuid.NewString()
	randURI := fmt.Sprintf("https://external-oidc-provider.com/%v", opState)

	mockClient := NewMockIssuerInteractionClient(gomock.NewController(t))
	mockStateStore := NewMockStateStore(gomock.NewController(t))

	mockClient.EXPECT().PushAuthorizationDetails(gomock.Any(), gomock.Any()).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer([]byte{})),
		}, nil)

	b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
		AuthorizationEndpoint: "https://issuer.example.com/authorize",
		AuthorizationRequest: issuer.OAuthParameters{
			ClientId:     "client_id",
			ClientSecret: "client_secret",
			ResponseType: "code",
			Scope:        []string{"openid"},
		},
		PushedAuthorizationRequestEndpoint: nil,
		TxId:                               "txID",
	})
	require.NoError(t, err)

	mockClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(b)),
	}, nil)

	mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	srv := testServer(t,
		withIssuerInteractionClient(mockClient),
		withStateStore(mockStateStore),
	)

	defer srv.Close()

	oauthClient := newOAuthClient(srv.URL)

	query := url.Values{}
	query.Set("client_id", oauthClient.ClientID)
	query.Set("client_secret", oauthClient.ClientSecret)
	query.Set("response_type", "code")
	query.Set("state", nonce(t))
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
	query.Set("code", nonce(t))
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

// serverOptions to customize test server.
type serverOptions struct {
	stateStore              oidc4vc.StateStore
	issuerInteractionClient oidc4vc.IssuerInteractionClient
}

// ServerOpt configures test server options.
type ServerOpt func(options *serverOptions)

func withStateStore(store oidc4vc.StateStore) ServerOpt {
	return func(o *serverOptions) {
		o.stateStore = store
	}
}

func withIssuerInteractionClient(client oidc4vc.IssuerInteractionClient) ServerOpt {
	return func(o *serverOptions) {
		o.issuerInteractionClient = client
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

	oauth2Provider := compose.Compose(config, fositeMemoryStore, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
	)

	controller := oidc4vc.NewController(&oidc4vc.Config{
		OAuth2Provider:          oauth2Provider,
		StateStore:              op.stateStore,
		IssuerInteractionClient: op.issuerInteractionClient,
	})

	oidc4vc.RegisterHandlers(e, controller)

	srv := httptest.NewServer(e)

	for _, client := range fositeMemoryStore.Clients {
		c, ok := client.(*fosite.DefaultClient)
		if ok {
			c.RedirectURIs[0] = srv.URL + "/redirect"
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

func newOAuthClient(serverURL string, opts ...ClientOpt) *oauth2.Config {
	op := &clientOptions{
		clientID: testClientID,
	}

	for _, fn := range opts {
		fn(op)
	}

	return &oauth2.Config{
		ClientID:     op.clientID,
		ClientSecret: "foobar",
		RedirectURL:  serverURL + "/redirect",
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			TokenURL:  serverURL + "/oidc/token",
			AuthURL:   serverURL + "/oidc/authorize",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func nonce(t *testing.T) string {
	t.Helper()

	b := make([]byte, nonceLength)

	_, err := rand.Read(b)
	if err != nil {
		require.NoError(t, err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}
