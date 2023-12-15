/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oidc4ci_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

	gojose "github.com/go-jose/go-jose/v3"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/proof/testsupport"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	oidc4cisrv "github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	profileID      = "testID"
	profileVersion = "v1.0"
)

func TestController_OidcPushedAuthorizationRequest(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
		q                     url.Values
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				mockOAuthProvider.EXPECT().NewPushedAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(&fosite.PushedAuthorizeResponse{}, nil)
				mockOAuthProvider.EXPECT().WritePushedAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

				mockInteractionClient.EXPECT().PushAuthorizationDetails(gomock.Any(), gomock.Any()).Return(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer(nil)),
					}, nil)

				q = url.Values{}
				q.Add("op_state", "opState")
				q.Add("authorization_details", `{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "invalid pushed authorize request",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(nil, errors.New("par error"))
				q = url.Values{}
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "par error")
			},
		},
		{
			name: "fail to unmarshal authorization details",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)

				q = url.Values{}
				q.Add("op_state", "opState")
				q.Add("authorization_details", "invalid")
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid-value[authorization_details]")
			},
		},
		{
			name: "fail to validate authorization details",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)

				q = url.Values{}
				q.Add("op_state", "opState")
				q.Add("authorization_details", `{"type":"invalid","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "type should be 'openid_credential'")
			},
		},
		{
			name: "fail to push authorization details",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				mockInteractionClient.EXPECT().PushAuthorizationDetails(gomock.Any(), gomock.Any()).Return(nil, errors.New("push authorization details error"))

				q = url.Values{}
				q.Add("op_state", "opState")
				q.Add("authorization_details", `{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "push authorization details error")
			},
		},
		{
			name: "invalid status code for push authorization details",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)

				mockInteractionClient.EXPECT().PushAuthorizationDetails(gomock.Any(), gomock.Any()).Return(
					&http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(bytes.NewBuffer(nil)),
					}, nil)

				q = url.Values{}
				q.Add("op_state", "opState")
				q.Add("authorization_details", `{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "push authorization details: status code")
			},
		},
		{
			name: "fail to create new pushed authorize response",
			setup: func() {
				mockOAuthProvider.EXPECT().NewPushedAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{}, nil)
				mockOAuthProvider.EXPECT().NewPushedAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("new pushed authorize response error"))

				mockInteractionClient.EXPECT().PushAuthorizationDetails(gomock.Any(), gomock.Any()).Return(
					&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBuffer(nil)),
					}, nil)

				q = url.Values{}
				q.Add("op_state", "opState")
				q.Add("authorization_details", `{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "new pushed authorize response error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				IssuerInteractionClient: mockInteractionClient,
				IssuerVCSPublicHost:     "https://issuer.example.com",
				Tracer:                  trace.NewNoopTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(q.Encode()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.OidcPushedAuthorizationRequest(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcAuthorize(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockStateStore        = NewMockStateStore(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
		mockHTTPClient        = NewMockHTTPClient(gomock.NewController(t))
		params                oidc4ci.OidcAuthorizeParams
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					State:                &state,
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(`{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockOAuthProvider.EXPECT().NewAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(
						ctx context.Context,
						ar fosite.AuthorizeRequester,
						session fosite.Session,
					) (fosite.AuthorizeResponder, error) {
						assert.Equal(t, *params.State, ar.(*fosite.AuthorizeRequest).State)

						return &fosite.AuthorizeResponse{}, nil
					},
				)

				b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
					AuthorizationRequest: issuer.OAuthParameters{},
				})
				require.NoError(t, err)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), *params.IssuerState, gomock.Any()).
					Return(nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusSeeOther, rec.Code)
				require.NotEmpty(t, rec.Header().Get("Location"))
			},
		},
		{
			name: "success wallet flow",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					State:                &state,
					IssuerState:          lo.ToPtr("https://some.issuer"),
					AuthorizationDetails: lo.ToPtr(`{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}`),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockOAuthProvider.EXPECT().NewAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(
						ctx context.Context,
						ar fosite.AuthorizeRequester,
						session fosite.Session,
					) (fosite.AuthorizeResponder, error) {
						assert.Equal(t, *params.State, ar.(*fosite.AuthorizeRequest).State)

						return &fosite.AuthorizeResponse{}, nil
					},
				)

				b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
					AuthorizationRequest: issuer.OAuthParameters{},
					WalletInitiatedFlow: &common.WalletInitiatedFlowData{
						OpState: "generated-op-state",
					},
				})
				require.NoError(t, err)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), "generated-op-state", gomock.Any()).
					Return(nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusSeeOther, rec.Code)
				require.NotEmpty(t, rec.Header().Get("Location"))
			},
		},
		{
			name: "success with par",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					IssuerState:  lo.ToPtr("opState"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockOAuthProvider.EXPECT().NewAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AuthorizeResponse{}, nil)

				parEndpoint := "https://localhost/par"
				parResponse := "https://localhost/authorize?request_uri=gfdsgfd2341321321"

				b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
					AuthorizationRequest:               issuer.OAuthParameters{},
					PushedAuthorizationRequestEndpoint: lo.ToPtr(parEndpoint),
				})
				require.NoError(t, err)

				mockHTTPClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusCreated,
							Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"request_uri":"%s"}`, parResponse))),
						}, nil
					},
				)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).DoAndReturn(
					func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					},
				)

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), *params.IssuerState, gomock.Any()).Return(nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusSeeOther, rec.Code)
				require.NotEmpty(t, rec.Header().Get("Location"))
			},
		},
		{
			name: "par error",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					IssuerState:  lo.ToPtr("opState"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockOAuthProvider.EXPECT().NewAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AuthorizeResponse{}, nil)

				parEndpoint := "https://localhost/par"

				b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
					AuthorizationRequest:               issuer.OAuthParameters{},
					PushedAuthorizationRequestEndpoint: lo.ToPtr(parEndpoint),
				})
				require.NoError(t, err)

				mockHTTPClient.EXPECT().Do(gomock.Any()).DoAndReturn(
					func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(bytes.NewBufferString("")),
						}, nil
					},
				)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).DoAndReturn(
					func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					},
				)

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), *params.IssuerState, gomock.Any()).
					Return(nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "unexpected status code")
			},
		},
		{
			name: "invalid authorize request",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					IssuerState:  lo.ToPtr("opState"),
				}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(nil,
					errors.New("authorize error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "authorize error")
			},
		},
		{
			name: "invalid authorization_details",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr("invalid"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(
					&fosite.AuthorizeRequest{
						Request: fosite.Request{RequestedScope: scope},
					}, nil,
				)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "authorization_details")
			},
		},
		{
			name: "fail to validate authorization_details",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(`{"type":"openid_credential","credential_type":"UniversityDegreeCredential","format":"invalid"}`),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "authorization_details.format")
			},
		},
		{
			name: "prepare claim data authorization",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					IssuerState:  lo.ToPtr("opState"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return nil, errors.New("prepare claim data authorization error")
					})
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "prepare claim data authorization")
			},
		},
		{
			name: "invalid status code for prepare claim data authorization",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					IssuerState:  lo.ToPtr("opState"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(bytes.NewBufferString(`{"code":"system-error","component":"OIDC4CIService","message":"unexpected transaction from 5 to 3","operation":"PrepareClaimDataAuthorizationRequest","incorrectValue":"state"}`)),
						}, nil
					})
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "prepare claim data authorization: status code")
			},
		},
		{
			name: "fail to create authorize response",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					State:        &state,
					IssuerState:  lo.ToPtr("opState"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockOAuthProvider.EXPECT().NewAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						ar fosite.AuthorizeRequester,
						session fosite.Session,
					) (fosite.AuthorizeResponder, error) {
						assert.Equal(t, *params.State, ar.(*fosite.AuthorizeRequest).State)

						return nil, errors.New("create authorize response error")
					})

				b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
					AuthorizationRequest: issuer.OAuthParameters{},
				})
				require.NoError(t, err)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "create authorize response error")
			},
		},
		{
			name: "fail to save authorize state",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType: "code",
					State:        &state,
					IssuerState:  lo.ToPtr("opState"),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)

				mockOAuthProvider.EXPECT().NewAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						ar fosite.AuthorizeRequester,
						session fosite.Session,
					) (fosite.AuthorizeResponder, error) {
						assert.Equal(t, *params.State, ar.(*fosite.AuthorizeRequest).State)

						return &fosite.AuthorizeResponse{}, nil
					})

				b, err := json.Marshal(&issuer.PrepareClaimDataAuthorizationResponse{
					AuthorizationRequest: issuer.OAuthParameters{},
				})
				require.NoError(t, err)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), *params.IssuerState, gomock.Any()).Return(
					errors.New("save state error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "save authorize state")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				StateStore:              mockStateStore,
				IssuerInteractionClient: mockInteractionClient,
				HTTPClient:              mockHTTPClient,
				IssuerVCSPublicHost:     "https://issuer.example.com",
			})

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.OidcAuthorize(echo.New().NewContext(req, rec), params)
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcRedirect(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockStateStore        = NewMockStateStore(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
		params                oidc4ci.OidcRedirectParams
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			setup: func() {
				params = oidc4ci.OidcRedirectParams{
					Code:  "code",
					State: "state",
				}

				redirectURI := &url.URL{Scheme: "https", Host: "example.com", Path: "redirect"}

				mockStateStore.EXPECT().GetAuthorizeState(gomock.Any(), params.State).Return(&oidc4cisrv.AuthorizeState{
					RedirectURI: redirectURI,
				}, nil)
				mockInteractionClient.EXPECT().StoreAuthorizationCodeRequest(
					gomock.Any(),
					issuer.StoreAuthorizationCodeRequest{
						Code:    params.Code,
						OpState: params.State,
					}).Return(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(nil))}, nil)

				mockOAuthProvider.EXPECT().WriteAuthorizeResponse(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(
						ctx context.Context,
						rw http.ResponseWriter,
						ar fosite.AuthorizeRequester,
						responder fosite.AuthorizeResponder,
					) {
						assert.Equal(t, redirectURI, ar.GetRedirectURI())
						assert.Equal(t, params.State, ar.GetState())
					})
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "fail to store code",
			setup: func() {
				params = oidc4ci.OidcRedirectParams{
					Code:  "code",
					State: "state",
				}

				redirectURI := &url.URL{Scheme: "https", Host: "example.com", Path: "redirect"}

				mockStateStore.EXPECT().GetAuthorizeState(gomock.Any(), params.State).Return(&oidc4cisrv.AuthorizeState{
					RedirectURI: redirectURI,
				}, nil)
				mockInteractionClient.EXPECT().StoreAuthorizationCodeRequest(
					gomock.Any(),
					issuer.StoreAuthorizationCodeRequest{
						Code:    params.Code,
						OpState: params.State,
					}).Return(nil, errors.New("random error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "random error")
			},
		},
		{
			name: "fail to get authorize state",
			setup: func() {
				params = oidc4ci.OidcRedirectParams{
					Code:  "code",
					State: "state",
				}

				mockStateStore.EXPECT().GetAuthorizeState(gomock.Any(), params.State).Return(nil, errors.New("get state error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "get state error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				StateStore:              mockStateStore,
				IssuerInteractionClient: mockInteractionClient,
				IssuerVCSPublicHost:     "https://issuer.example.com",
			})

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.OidcRedirect(echo.New().NewContext(req, rec), params)
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcToken(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			setup: func() {
				opState := uuid.NewString()
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{
								Extra: map[string]interface{}{
									"opState": opState,
								},
							},
							Client: &fosite.DefaultClient{
								ID: clientID,
							},
						},
					}, nil)

				mockInteractionClient.EXPECT().ExchangeAuthorizationCodeRequest(gomock.Any(),
					issuer.ExchangeAuthorizationCodeRequestJSONRequestBody{
						OpState:             opState,
						ClientId:            lo.ToPtr(clientID),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"tx_id":"txID"}`)),
						}, nil)

				mockOAuthProvider.EXPECT().NewAccessResponse(gomock.Any(), gomock.Any()).Return(
					fosite.NewAccessResponse(), nil)

				mockOAuthProvider.EXPECT().WriteAccessResponse(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "fail to create new access request",
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					nil, errors.New("new access request error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "new access request error")
			},
		},
		{
			name: "fail to create new access response",
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{
								Extra: map[string]interface{}{
									"opState": "1234",
								},
							},
							Client: &fosite.DefaultClient{
								ID: clientID,
							},
						},
					}, nil)

				mockInteractionClient.EXPECT().ExchangeAuthorizationCodeRequest(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(`{"tx_id":"txID"}`)),
						}, nil)

				mockOAuthProvider.EXPECT().NewAccessResponse(gomock.Any(), gomock.Any()).Return(
					nil, errors.New("new access response error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "new access response error")
			},
		},
		{
			name: "fail to exchange token",
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{
								Extra: map[string]interface{}{
									"opState": "1234",
								},
							},
							Client: &fosite.DefaultClient{
								ID: clientID,
							},
						},
					}, nil)

				mockInteractionClient.EXPECT().ExchangeAuthorizationCodeRequest(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("can not exchange token"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "can not exchange token")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				IssuerInteractionClient: mockInteractionClient,
				Tracer:                  trace.NewNoopTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.OidcToken(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcCredential(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
		accessToken           string
		requestBody           []byte
	)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	proofCreator, proofChecker := testsupport.NewEd25519Pair(publicKey, privateKey, testsupport.AnyPubKeyID)

	headers := map[string]interface{}{
		jose.HeaderType: "openid4vci-proof+jwt",
	}

	currentTime := time.Now().Unix()

	signedJWT, err := jwt.NewSigned(&oidc4ci.JWTProofClaims{
		Issuer:   clientID,
		IssuedAt: &currentTime,
		Nonce:    "c_nonce",
		Audience: aud,
	}, jwt.SignParameters{
		JWTAlg:            "EdDSA",
		KeyID:             "Any",
		AdditionalHeaders: headers,
	}, proofCreator)
	require.NoError(t, err)

	jws, err := signedJWT.Serialize(false)
	require.NoError(t, err)

	credentialReq := oidc4ci.CredentialRequest{
		Format: lo.ToPtr(string(common.JwtVcJsonLd)),
		Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: jws},
		Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
	}

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success preAuth",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				b, marshalErr := json.Marshal(issuer.PrepareCredentialResult{
					Credential: "credential in jwt format",
					Format:     string(verifiable.Jwt),
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "success auth",
			setup: func() {
				ar := fosite.NewAccessRequest(
					&fosite.DefaultSession{
						Extra: map[string]interface{}{
							"txID":            "tx_id",
							"cNonce":          "c_nonce",
							"preAuth":         false,
							"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
						},
					},
				)
				ar.Client = &fosite.DefaultClient{ID: clientID}

				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken, ar, nil)

				b, marshalErr := json.Marshal(issuer.PrepareCredentialResult{
					Credential: "credential in jwt format",
					Format:     string(verifiable.Jwt),
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "invalid credential format",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr("invalid"),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: jws},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "unsupported vc format")
			},
		},
		{
			name: "missing proof type",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  nil,
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "missing proof type")
			},
		},
		{
			name: "invalid proof type",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: ""},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid proof type")
			},
		},
		{
			name: "missing access token",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = ""

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "missing access token")
			},
		},
		{
			name: "fail to introspect token",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(fosite.AccessToken, nil, errors.New("introspect error"))

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "introspect token")
			},
		},
		{
			name: "fail to parse proof jwt",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: "invalid jws"},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "parse jwt")
			},
		},
		{
			name: "nonce expired",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(-time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "nonce expired")
			},
		},
		{
			name: "invalid jwt claims",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				var signedJWTInvalid *jwt.JSONWebToken
				signedJWTInvalid, err = jwt.NewSigned(map[string]interface{}{
					"iss": 123,
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, err)

				var jwsInvalid string
				jwsInvalid, err = signedJWTInvalid.Serialize(false)
				require.NoError(t, err)

				credentialReqInvalid := oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: jwsInvalid},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				}

				requestBody, err = json.Marshal(credentialReqInvalid)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid jwt claims")
			},
		},
		{
			name: "invalid client_id - missing in session",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(fosite.AccessToken, fosite.NewAccessRequest(
						&fosite.DefaultSession{
							Extra: map[string]interface{}{
								"txID":            "tx_id",
								"cNonce":          "c_nonce",
								"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
							},
						},
					), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid client_id")
			},
		},
		{
			name: "invalid client_id",
			setup: func() {
				ar := fosite.NewAccessRequest(
					&fosite.DefaultSession{
						Extra: map[string]interface{}{
							"txID":            "tx_id",
							"cNonce":          "c_nonce",
							"preAuth":         false,
							"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
						},
					},
				)

				ar.Client = &fosite.DefaultClient{ID: "invalid"}

				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(fosite.AccessToken, ar, nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid client_id")
			},
		},
		{
			name: "invalid aud",
			setup: func() {
				ar := fosite.NewAccessRequest(
					&fosite.DefaultSession{
						Extra: map[string]interface{}{
							"txID":            "tx_id",
							"cNonce":          "c_nonce",
							"preAuth":         false,
							"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
						},
					},
				)
				ar.Client = &fosite.DefaultClient{ID: clientID}

				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken, ar, nil)

				responseBody := `{"code":"invalidor-missing-proof","incorrectValue":"badAud","message":"invalid aud"}`

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid aud")
			},
		},
		{
			name: "missing iat",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				var signedJWTInvalid *jwt.JSONWebToken
				signedJWTInvalid, err = jwt.NewSigned(&oidc4ci.JWTProofClaims{
					Issuer:   clientID,
					Nonce:    "c_nonce",
					Audience: aud,
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, err)

				var jwsInvalid string
				jwsInvalid, err = signedJWTInvalid.Serialize(false)
				require.NoError(t, err)

				credentialReqInvalid := oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: jwsInvalid},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				}

				requestBody, err = json.Marshal(credentialReqInvalid)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "missing iat")
			},
		},
		{
			name: "invalid nonce",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.JWTProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "invalid",
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: invalidJWS},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid nonce")
			},
		},
		{
			name: "missed typ",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.JWTProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "c_nonce",
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: invalidJWS},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(requestBody)),
						}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "invalid typ",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				invalidHeaders := map[string]interface{}{
					jose.HeaderType: jwt.TypeJWT,
				}

				currentTime := time.Now().Unix()

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.JWTProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "c_nonce",
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any", AdditionalHeaders: invalidHeaders}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: invalidJWS},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "invalid typ")
			},
		},
		{
			name: "invalid kid",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)

				accessToken = "access-token"

				currentTime := time.Now().Unix()

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.JWTProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "c_nonce",
				}, jwt.SignParameters{
					JWTAlg:            "EdDSA",
					AdditionalHeaders: headers,
				}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					Proof:  &oidc4ci.JWTProof{ProofType: "jwt", Jwt: invalidJWS},
					Types:  []string{"VerifiableCredential", "UniversityDegreeCredential"},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "missed kid in jwt header")
			},
		},
		{
			name: "fail to prepare credential",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("prepare credential error"))

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "prepare credential")
			},
		},
		{
			name: "invalid status code in prepare credential response (format)",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "oidc-credential-format-not-supported"}`)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err,
					"oidc-error: prepare credential: status code 500, "+
						"code: oidc-credential-format-not-supported")
			},
		},
		{
			name: "invalid status code in prepare credential response (invalid json)",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{`)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "prepare credential: status code 500, {")
			},
		},
		{
			name: "invalid status code in prepare credential response (type)",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "oidc-credential-type-not-supported"}`)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err,
					"oidc-error: prepare credential: status code 500, "+
						"code: oidc-credential-type-not-supported")
			},
		},
		{
			name: "invalid status code in prepare credential response (random)",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "random", "message": "awesome"}`)),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err,
					"prepare credential: status code 500, code: random; message: awesome")
			},
		},
		{
			name: "fail to decode prepare credential result",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).
					Return(
						fosite.AccessToken,
						fosite.NewAccessRequest(
							&fosite.DefaultSession{
								Extra: map[string]interface{}{
									"txID":            "tx_id",
									"cNonce":          "c_nonce",
									"preAuth":         true,
									"cNonceExpiresAt": time.Now().Add(time.Minute).Unix(),
								},
							},
						), nil)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString("invalid json")),
						}, nil)

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "decode prepare credential result")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				IssuerInteractionClient: mockInteractionClient,
				JWTVerifier:             proofChecker,
				Tracer:                  trace.NewNoopTracerProvider().Tracer(""),
				IssuerVCSPublicHost:     aud,
			})

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			if accessToken != "" {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			}

			rec := httptest.NewRecorder()

			err := controller.OidcCredential(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcPreAuthorize(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
	)

	tests := []struct {
		name  string
		body  io.Reader
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"123456"},
				"user_pin":            {"5678"},
			}.Encode()),
			setup: func() {
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), gomock.Any()).
					Return(&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"scopes" : ["a","b"], "op_state" : "opp123"}`)),
					}, nil)

				accessRq := &fosite.AccessRequest{
					Request: fosite.Request{
						Session: &fosite.DefaultSession{},
					},
				}

				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(accessRq, nil)

				mockOAuthProvider.EXPECT().NewAccessResponse(gomock.Any(), accessRq).
					Return(&fosite.AccessResponse{
						AccessToken: "123456",
						Extra: map[string]interface{}{
							"expires_in": 3600,
						},
					}, nil)

				mockOAuthProvider.EXPECT().WriteAccessResponse(gomock.Any(), gomock.Any(), accessRq, gomock.Any()).
					Do(func(ctx context.Context, rw http.ResponseWriter, requester fosite.AccessRequester, responder fosite.AccessResponder) {
						js, err := json.Marshal(responder.ToMap())
						if err != nil {
							http.Error(rw, err.Error(), http.StatusInternalServerError)
							return
						}

						rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

						rw.WriteHeader(http.StatusOK)
						_, _ = rw.Write(js)
					})
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.NoError(t, err)
				var resp oidc4ci.AccessTokenResponse

				assert.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
				assert.Equal(t, "123456", resp.AccessToken)
				assert.NotEmpty(t, *resp.ExpiresIn)
			},
		},
		{
			name: "name invalid pre-auth code",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"123456"},
				"user_pin":            {"5678"},
				"client_id":           {clientID},
			}.Encode()),
			setup: func() {
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
					issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
						PreAuthorizedCode:   "123456",
						UserPin:             lo.ToPtr("5678"),
						ClientId:            lo.ToPtr(clientID),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).Return(nil, errors.New("invalid pin"))

				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{},
						},
					}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "invalid pin")
			},
		},
		{
			name: "invalid response from validator",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"321"},
				"client_id":           {clientID},
			}.Encode()),
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{},
						},
					}, nil)
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
					issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
						PreAuthorizedCode:   "321",
						UserPin:             lo.ToPtr(""),
						ClientId:            lo.ToPtr(clientID),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader("{")),
					StatusCode: http.StatusOK,
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "unexpected EOF")
			},
		},
		{
			name: "invalid http code from validate pre authorize",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"321"},
				"client_id":           {clientID},
			}.Encode()),
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{},
						},
					}, nil)
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
					issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
						PreAuthorizedCode:   "321",
						UserPin:             lo.ToPtr(""),
						ClientId:            lo.ToPtr(clientID),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader("{}")),
					StatusCode: http.StatusBadRequest,
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "validate pre-authorized code request: status code 400, code")
			},
		},
		{
			name: "invalid tx validate pre authorize",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"321"},
				"client_id":           {clientID},
			}.Encode()),
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{},
						},
					}, nil)
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
					issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
						PreAuthorizedCode:   "321",
						UserPin:             lo.ToPtr(""),
						ClientId:            lo.ToPtr(clientID),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader(`{"code": "oidc-tx-not-found"}`)),
					StatusCode: http.StatusBadRequest,
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err,
					"oidc-error: validate pre-authorized code request: status code 400, "+
						"code: oidc-tx-not-found")
			},
		},
		{
			name: "invalid expect pin pre authorize",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"321"},
				"client_id":           {clientID},
			}.Encode()),
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{},
						},
					}, nil)
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
					issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
						PreAuthorizedCode:   "321",
						UserPin:             lo.ToPtr(""),
						ClientId:            lo.ToPtr(clientID),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader(`{"code": "oidc-pre-authorize-expect-pin"}`)),
					StatusCode: http.StatusBadRequest,
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err,
					"oidc-error: validate pre-authorized code request: status code 400, "+
						"code: oidc-pre-authorize-expect-pin")
			},
		},
		{
			name: "invalid client id pre authorize",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"321"},
			}.Encode()),
			setup: func() {
				mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&fosite.AccessRequest{
						Request: fosite.Request{
							Session: &fosite.DefaultSession{},
						},
					}, nil)
				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(),
					issuer.ValidatePreAuthorizedCodeRequestJSONRequestBody{
						PreAuthorizedCode:   "321",
						UserPin:             lo.ToPtr(""),
						ClientId:            lo.ToPtr(""),
						ClientAssertionType: lo.ToPtr(""),
						ClientAssertion:     lo.ToPtr(""),
					}).Return(&http.Response{
					Body:       io.NopCloser(strings.NewReader(`{"code": "oidc-pre-authorize-invalid-client-id"}`)),
					StatusCode: http.StatusBadRequest,
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err,
					"oidc-error: validate pre-authorized code request: status code 400, "+
						"code: oidc-pre-authorize-invalid-client-id")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				IssuerInteractionClient: mockInteractionClient,
				Tracer:                  trace.NewNoopTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodPost, "/", tt.body)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.OidcToken(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestController_Ack(t *testing.T) {
	hh := func(text string) string {
		hash := sha256.Sum256([]byte(text))
		return hex.EncodeToString(hash[:])
	}

	t.Run("success", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		expectedToken := "xxxx"

		ackMock.EXPECT().Ack(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, remote oidc4cisrv.AckRemote) error {
				assert.Equal(t, hh(expectedToken), remote.HashedToken)
				assert.Equal(t, "tx_id", remote.ID)
				assert.Equal(t, "status", remote.Status)
				assert.Equal(t, "err_txt", remote.ErrorText)

				return nil
			})

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"credentials" : [{"ack_id" : "tx_id", "status" : "status", "error_description" : "err_txt"}]
		}`)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Authorization", "Bearer xxxx")
		rec := httptest.NewRecorder()

		err := controller.OidcAcknowledgement(echo.New().NewContext(req, rec))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("ack err", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		ackMock.EXPECT().Ack(gomock.Any(), gomock.Any()).
			Return(errors.New("some error"))

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"credentials" : [{"ack_id" : "tx_id", "status" : "status", "error_description" : "err_txt"}]
		}`)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Authorization", "Bearer xxxx")

		rec := httptest.NewRecorder()

		err := controller.OidcAcknowledgement(echo.New().NewContext(req, rec))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var bd oidc4ci.AckErrorResponse
		b, _ := io.ReadAll(rec.Body)

		assert.NoError(t, json.Unmarshal(b, &bd))
		assert.Equal(t, "some error", bd.Error)
	})

	t.Run("token err 2", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"credentials" : [{"ack_id" : "tx_id", "status" : "status", "error_description" : "err_txt"}]
		}`)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		err := controller.OidcAcknowledgement(echo.New().NewContext(req, rec))
		assert.ErrorContains(t, err, "missing access token")
	})

	t.Run("ack expired", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         trace.NewNoopTracerProvider().Tracer(""),
		})

		ackMock.EXPECT().Ack(gomock.Any(), gomock.Any()).
			Return(oidc4cisrv.ErrAckExpired)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"credentials" : [{"ack_id" : "tx_id", "status" : "status", "error_description" : "err_txt"}]
		}`)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Authorization", "Bearer xxxx")

		rec := httptest.NewRecorder()

		err := controller.OidcAcknowledgement(echo.New().NewContext(req, rec))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var bd oidc4ci.AckErrorResponse
		b, _ := io.ReadAll(rec.Body)

		assert.NoError(t, json.Unmarshal(b, &bd))
		assert.Equal(t, "expired_ack_id", bd.Error)
	})
}

func TestController_OidcRegisterClient(t *testing.T) {
	mockClientManager := NewMockClientManager(gomock.NewController(t))
	mockProfileService := NewMockProfileService(gomock.NewController(t))

	reqBody, err := json.Marshal(&oidc4ci.RegisterOAuthClientRequest{
		ClientName:   lo.ToPtr("client-name"),
		ClientUri:    lo.ToPtr("https://example.com"),
		GrantTypes:   lo.ToPtr([]string{"authorization_code"}),
		RedirectUris: lo.ToPtr([]string{"https://example.com/callback"}),
	})
	require.NoError(t, err)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, rec *httptest.ResponseRecorder, err error)
	}{
		{
			name: "success",
			setup: func() {
				mockProfileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{EnableDynamicClientRegistration: true},
					}, nil)

				mockClientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&oauth2client.Client{
						ID:                      uuid.New().String(),
						Name:                    "client-name",
						URI:                     "https://example.com",
						Secret:                  []byte("secret"),
						SecretExpiresAt:         0,
						RedirectURIs:            []string{"https://example.com/callback"},
						GrantTypes:              []string{"authorization_code"},
						ResponseTypes:           []string{"code"},
						Scopes:                  []string{"openid", "profile"},
						LogoURI:                 "https://example.com/logo",
						Contacts:                []string{"contact@example.com"},
						TermsOfServiceURI:       "https://example.com/tos",
						PolicyURI:               "https://example.com/policy",
						JSONWebKeysURI:          "https://example.com/jwks",
						JSONWebKeys:             &gojose.JSONWebKeySet{},
						SoftwareID:              "software-id",
						SoftwareVersion:         "software-version",
						TokenEndpointAuthMethod: "basic",
						CreatedAt:               time.Now(),
					}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.NoError(t, err)
				assert.Equal(t, http.StatusCreated, rec.Code)
			},
		},
		{
			name: "no empty metadata fields",
			setup: func() {
				mockProfileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{EnableDynamicClientRegistration: true},
					}, nil)

				mockClientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					&oauth2client.Client{
						ID: uuid.New().String(),
					}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var resp oidc4ci.RegisterOAuthClientResponse

				assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				assert.Equal(t, http.StatusCreated, rec.Code)

				assert.Nil(t, resp.ClientName)
				assert.Nil(t, resp.ClientSecret)
				assert.Nil(t, resp.ClientSecretExpiresAt)
				assert.Nil(t, resp.ClientUri)
				assert.Nil(t, resp.Contacts)
				assert.Nil(t, resp.Jwks)
				assert.Nil(t, resp.JwksUri)
				assert.Nil(t, resp.LogoUri)
				assert.Nil(t, resp.PolicyUri)
				assert.Nil(t, resp.RedirectUris)
				assert.Nil(t, resp.ResponseTypes)
				assert.Nil(t, resp.Scope)
				assert.Nil(t, resp.SoftwareId)
				assert.Nil(t, resp.SoftwareVersion)
				assert.Nil(t, resp.TosUri)
			},
		},
		{
			name: "fail to get profile",
			setup: func() {
				mockProfileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("get profile error"))

				mockClientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var customErr *resterr.CustomError

				assert.ErrorAs(t, err, &customErr)
				assert.ErrorContains(t, customErr, "get profile error")
				assert.Equal(t, resterr.SystemError, customErr.Code)
				assert.Equal(t, "issuer.profile-service", customErr.Component)
				assert.Equal(t, "GetProfile", customErr.FailedOperation)
			},
		},
		{
			name: "dynamic client registration disabled",
			setup: func() {
				mockProfileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{EnableDynamicClientRegistration: false},
					}, nil)

				mockClientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				assert.ErrorContains(t, err, "dynamic client registration not supported")
			},
		},
		{
			name: "client registration error",
			setup: func() {
				mockProfileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{EnableDynamicClientRegistration: true},
					}, nil)

				mockClientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil,
					&clientmanager.RegistrationError{
						Code:         clientmanager.ErrCodeInvalidClientMetadata,
						InvalidValue: "scope",
						Err:          fmt.Errorf("scope invalid not supported"),
					})
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var regErr *resterr.RegistrationError

				assert.ErrorAs(t, err, &regErr)
				assert.ErrorContains(t, regErr.Err, "scope invalid not supported")
				assert.Equal(t, "invalid_client_metadata", regErr.Code)
			},
		},
		{
			name: "create client error",
			setup: func() {
				mockProfileService.EXPECT().GetProfile(gomock.Any(), gomock.Any()).Return(
					&profileapi.Issuer{
						OIDCConfig: &profileapi.OIDCConfig{EnableDynamicClientRegistration: true},
					}, nil)

				mockClientManager.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil,
					fmt.Errorf("create client error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var customErr *resterr.CustomError

				assert.ErrorAs(t, err, &customErr)
				assert.ErrorContains(t, customErr, "create client error")
				assert.Equal(t, resterr.SystemError, customErr.Code)
				assert.Equal(t, "client-manager", customErr.Component)
				assert.Equal(t, "Create", customErr.FailedOperation)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			controller := oidc4ci.NewController(&oidc4ci.Config{
				ClientManager:  mockClientManager,
				ProfileService: mockProfileService,
				Tracer:         trace.NewNoopTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			rec := httptest.NewRecorder()

			err := controller.OidcRegisterClient(echo.New().NewContext(req, rec), profileID, profileVersion)
			tt.check(t, rec, err)
		})
	}
}
