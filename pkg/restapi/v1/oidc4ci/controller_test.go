/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:lll
package oidc4ci_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
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

	"github.com/fxamacker/cbor/v2"
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
	verifiable2 "github.com/trustbloc/vc-go/verifiable"
	"github.com/veraison/go-cose"
	nooptracer "go.opentelemetry.io/otel/trace/noop"

	"github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/oauth2client"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
	"github.com/trustbloc/vcs/pkg/service/clientmanager"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	oidc4cisrv "github.com/trustbloc/vcs/pkg/service/oidc4ci"
)

const (
	profileID      = "testID"
	profileVersion = "v1.0"
)

var (
	//nolint:gochecknoglobals
	authorizationDetailsFormatBased = `[{
    "type": "openid_credential",
    "format": "ldp_vc",
    "credential_definition": {
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ],
      "credentialSubject": {
        "given_name": {},
        "family_name": {},
        "degree": {}
      }
    }
  }]`
	//nolint:gochecknoglobals
	authorizationDetailsCredentialConfigurationIDBased = `[{
		 "type": "openid_credential",
		 "credential_configuration_id": "UniversityDegreeCredential"
		}]`
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
			name: "success: AuthorizationDetails contains Format field",
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
				q.Add("authorization_details", authorizationDetailsFormatBased)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name: "success: AuthorizationDetails contains CredentialConfigurationID field",
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
				q.Add("authorization_details", authorizationDetailsCredentialConfigurationIDBased)
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
				q.Add("authorization_details", `[{"type":"invalid","credential_type":"UniversityDegreeCredential","format":"ldp_vc"}]`)
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
				q.Add("authorization_details", authorizationDetailsFormatBased)
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
				q.Add("authorization_details", authorizationDetailsFormatBased)
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
				q.Add("authorization_details", authorizationDetailsFormatBased)
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
				Tracer:                  nooptracer.NewTracerProvider().Tracer(""),
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
			name: "success format based",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					State:                &state,
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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
					ProfileAuthStateTtl:  10,
				})
				require.NoError(t, err)

				mockInteractionClient.EXPECT().PrepareAuthorizationRequest(gomock.Any(), gomock.Any()).
					DoAndReturn(func(
						ctx context.Context,
						req issuer.PrepareAuthorizationRequestJSONRequestBody,
						reqEditors ...issuer.RequestEditorFn,
					) (*http.Response, error) {
						var authorizationDetails *[]common.AuthorizationDetails
						err = json.Unmarshal([]byte(authorizationDetailsFormatBased), &authorizationDetails)
						assert.NoError(t, err)
						assert.Equal(t, authorizationDetails, req.AuthorizationDetails)
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(10), *params.IssuerState, gomock.Any()).
					Return(nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusSeeOther, rec.Code)
				require.NotEmpty(t, rec.Header().Get("Location"))
			},
		},
		{
			name: "success CredentialConfigurationId based",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					State:                &state,
					AuthorizationDetails: lo.ToPtr(authorizationDetailsCredentialConfigurationIDBased),
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
						var authorizationDetails *[]common.AuthorizationDetails
						err = json.Unmarshal([]byte(authorizationDetailsCredentialConfigurationIDBased), &authorizationDetails)
						assert.NoError(t, err)
						assert.Equal(t, authorizationDetails, req.AuthorizationDetails)
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.NotEmpty(t, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(0), gomock.Any(), gomock.Any()).
					Return(nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusSeeOther, rec.Code)
				require.NotEmpty(t, rec.Header().Get("Location"))
			},
		},
		{
			name: "Success: AuthorizationDetails not supplied",
			setup: func() {
				state := "state"

				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					State:                &state,
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: nil,
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
						assert.Nil(t, req.AuthorizationDetails)
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(0), *params.IssuerState, gomock.Any()).
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
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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
						var authorizationDetails *[]common.AuthorizationDetails
						err = json.Unmarshal([]byte(authorizationDetailsFormatBased), &authorizationDetails)
						assert.NoError(t, err)
						assert.Equal(t, authorizationDetails, req.AuthorizationDetails)
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					})

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(0), "generated-op-state", gomock.Any()).
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
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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
						var authorizationDetails *[]common.AuthorizationDetails
						err = json.Unmarshal([]byte(authorizationDetailsFormatBased), &authorizationDetails)
						assert.NoError(t, err)
						assert.Equal(t, authorizationDetails, req.AuthorizationDetails)
						assert.Equal(t, params.ResponseType, req.ResponseType)
						assert.Equal(t, *params.IssuerState, req.OpState)
						assert.Equal(t, lo.ToPtr(scope), req.Scope)

						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil
					},
				)

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(0), *params.IssuerState, gomock.Any()).Return(nil)
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
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(0), *params.IssuerState, gomock.Any()).
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
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
				}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(nil,
					errors.New("authorize error"))
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "authorize error")
			},
		},
		{
			name: "invalid authorization_details payload",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(`{"key":"value"}`),
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
					AuthorizationDetails: lo.ToPtr(`[{"type": "invalid"}]`),
				}

				scope := []string{"openid", "profile"}

				mockOAuthProvider.EXPECT().NewAuthorizeRequest(gomock.Any(), gomock.Any()).Return(&fosite.AuthorizeRequest{
					Request: fosite.Request{RequestedScope: scope},
				}, nil)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "type should be 'openid_credential'")
			},
		},
		{
			name: "prepare claim data authorization",
			setup: func() {
				params = oidc4ci.OidcAuthorizeParams{
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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
					ResponseType:         "code",
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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
					ResponseType:         "code",
					State:                &state,
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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
					ResponseType:         "code",
					State:                &state,
					IssuerState:          lo.ToPtr("opState"),
					AuthorizationDetails: lo.ToPtr(authorizationDetailsFormatBased),
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

				mockStateStore.EXPECT().SaveAuthorizeState(gomock.Any(), int32(0), *params.IssuerState, gomock.Any()).Return(
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

func TestController_OidcToken_Authorize(t *testing.T) {
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
				ad := getTestOIDCTokenAuthorizationDetailsPayload(t)
				payload := fmt.Sprintf(`{"tx_id":"txID", "authorization_details": %s}`, ad)

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
							Body:       io.NopCloser(bytes.NewBufferString(payload)),
						}, nil)

				mockOAuthProvider.EXPECT().NewAccessResponse(gomock.Any(), gomock.Any()).Return(
					fosite.NewAccessResponse(), nil)

				mockOAuthProvider.EXPECT().WriteAccessResponse(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
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
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				var resp oidc4ci.AccessTokenResponse

				assert.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

				ad := *resp.AuthorizationDetails
				assert.Len(t, ad, 1)
				assert.Equal(t, "openid_credential", ad[0].Type)
			},
		},
		{
			name: "success no authorization detail in response",
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

				mockOAuthProvider.EXPECT().WriteAccessResponse(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
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
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				var resp oidc4ci.AccessTokenResponse

				assert.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

				assert.Nil(t, resp.AuthorizationDetails)
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
				Tracer:                  nooptracer.NewTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

			rec := httptest.NewRecorder()

			err := controller.OidcToken(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestMissingProof(t *testing.T) {
	testCases := []struct {
		proofType   string
		expectedErr string
	}{
		{
			proofType:   "cwt",
			expectedErr: "missing cwt proof",
		},
		{
			proofType:   "ldp_vp",
			expectedErr: "missing ldp_vp proof",
		},
		{
			proofType:   "xxx",
			expectedErr: "invalid proof type",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.proofType, func(t *testing.T) {
			mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))
			mockInteractionClient := NewMockIssuerInteractionClient(gomock.NewController(t))

			ctr := oidc4ci.NewController(&oidc4ci.Config{
				OAuth2Provider:          mockOAuthProvider,
				IssuerInteractionClient: mockInteractionClient,
				Tracer:                  nooptracer.NewTracerProvider().Tracer(""),
			})

			credReq := oidc4ci.CredentialRequest{
				Format: lo.ToPtr("jwt_vc_json"),
				Proof: &oidc4ci.JWTProof{
					ProofType: testCase.proofType,
				},
			}
			var requestBody []byte
			requestBody, err := json.Marshal(credReq)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()

			err = ctr.OidcCredential(echo.New().NewContext(req, rec))
			assert.ErrorContains(t, err, testCase.expectedErr)
		})
	}
}

func TestController_OidcCredential(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
		jweEncrypterCreator   func(jwk gojose.JSONWebKey, alg gojose.KeyAlgorithm, enc gojose.ContentEncryption) (gojose.Encrypter, error) //nolint:lll
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

	signedJWT, err := jwt.NewSigned(&oidc4ci.ProofClaims{
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
		CredentialDefinition: &common.CredentialDefinition{
			Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
		Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	defaultJWEEncrypterCreator := func(jwk gojose.JSONWebKey, alg gojose.KeyAlgorithm, enc gojose.ContentEncryption) (gojose.Encrypter, error) { //nolint:lll
		return gojose.NewEncrypter(
			enc,
			gojose.Recipient{
				Algorithm: alg,
				Key:       jwk,
			},
			nil,
		)
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
					Credential:     "credential in jwt format",
					Format:         string(verifiable.Jwt),
					NotificationId: "notificationID",
					Credentials: []common.CredentialResponseCredentialObject{
						{
							Credential: "credential in jwt format",
						},
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				var resp *oidc4ci.CredentialResponse
				require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

				assert.NotEmpty(t, resp.CNonce)
				assert.Equal(t, "credential in jwt format", resp.Credential)
				assert.Equal(t, []common.CredentialResponseCredentialObject{{Credential: "credential in jwt format"}}, resp.Credentials)
				assert.Equal(t, "notificationID", resp.NotificationId)
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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
			name: "success with encrypted credential response",
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
					CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
						Alg: string(gojose.ECDH_ES),
						Enc: string(gojose.A128CBC_HS256),
						Jwk: string(b),
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
				require.Equal(t, "application/jwt", rec.Header().Get("Content-Type"))

				jwe, err := gojose.ParseEncrypted(rec.Body.String())
				require.NoError(t, err)

				decrypted, err := jwe.Decrypt(ecdsaPrivateKey)
				require.NoError(t, err)

				var resp *oidc4ci.CredentialResponse
				require.NoError(t, json.Unmarshal(decrypted, &resp))

				require.Equal(t, "credential in jwt format", resp.Credential)
				require.NotEmpty(t, resp.CNonce)
				require.NotEmpty(t, resp.CNonceExpiresIn)
			},
		},
		{
			name: "invalid credential format",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr("invalid"),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
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
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: nil,
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
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: nil},
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
				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: lo.ToPtr("invalid jws")},
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jwsInvalid},
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				var signedJWTInvalid *jwt.JSONWebToken
				signedJWTInvalid, err = jwt.NewSigned(&oidc4ci.ProofClaims{
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
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jwsInvalid},
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
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
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
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
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				// typ is required per spec
				require.ErrorContains(t, err, "invalid typ")
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				invalidHeaders := map[string]interface{}{
					jose.HeaderType: jwt.TypeJWT,
				}

				currentTime := time.Now().Unix()

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
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
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				currentTime := time.Now().Unix()

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
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
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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

				jweEncrypterCreator = defaultJWEEncrypterCreator

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
			name: "invalid encryption parameters",
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
							Body:       io.NopCloser(strings.NewReader(`{"code" : "oidc-invalid-encryption-parameters"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "oidc-invalid-encryption-parameters")
			},
		},
		{
			name: "invalid or missing proof",
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
							Body:       io.NopCloser(strings.NewReader(`{"code" : "invalid_or_missing_proof", "message": "invalid or missing proof"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var customErr *resterr.CustomError

				assert.ErrorAs(t, err, &customErr)
				assert.ErrorContains(t, customErr, "oidc-error: invalid or missing proof")
				assert.Equal(t, resterr.OIDCError, customErr.Code)
				assert.Equal(t, "invalid_or_missing_proof", customErr.Component)
				assert.Empty(t, customErr.FailedOperation)
			},
		},
		{
			name: "invalid credentials request",
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
							Body:       io.NopCloser(strings.NewReader(`{"code" : "invalid_credential_request"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var customErr *resterr.CustomError

				assert.ErrorAs(t, err, &customErr)
				assert.ErrorContains(t, customErr, "oidc-error: prepare credential: status code 500, code: invalid_credential_request")
				assert.Equal(t, resterr.OIDCError, customErr.Code)
				assert.Equal(t, "invalid_credential_request", customErr.Component)
				assert.Empty(t, customErr.FailedOperation)
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(credentialReq)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "decode prepare credential result")
			},
		},
		{
			name: "fail to unmarshal jwk for encrypting credential response",
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
					CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
						Alg: string(gojose.ECDH_ES),
						Enc: string(gojose.A128CBC_HS256),
						Jwk: "invalid jwk",
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "unmarshal jwk")
			},
		},
		{
			name: "fail to create encrypter for encrypting credential response",
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
					CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
						Alg: string(gojose.ED25519),
						Enc: string(gojose.A128CBC_HS256),
						Jwk: string(b),
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "create encrypter")
			},
		},
		{
			name: "fail to encrypt credential response",
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

				jweEncrypterCreator = func(gojose.JSONWebKey, gojose.KeyAlgorithm, gojose.ContentEncryption) (gojose.Encrypter, error) { //nolint:lll,unparam
					return &mockJWEEncrypter{
						Err: errors.New("encrypt error"),
					}, nil
				}

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
					CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
						Alg: string(gojose.ECDH_ES),
						Enc: string(gojose.A128CBC_HS256),
						Jwk: string(b),
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "encrypt credential response")
			},
		},
		{
			name: "fail to serialize encrypted credential response",
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

				jweEncrypterCreator = func(gojose.JSONWebKey, gojose.KeyAlgorithm, gojose.ContentEncryption) (gojose.Encrypter, error) { //nolint:lll,unparam
					return &mockJWEEncrypter{
						JWE: &gojose.JSONWebEncryption{},
					}, nil
				}

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.CredentialRequest{
					Format: lo.ToPtr(string(common.JwtVcJsonLd)),
					CredentialDefinition: &common.CredentialDefinition{
						Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
					CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
						Alg: string(gojose.ECDH_ES),
						Enc: string(gojose.A128CBC_HS256),
						Jwk: string(b),
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "serialize credential response")
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
				Tracer:                  nooptracer.NewTracerProvider().Tracer(""),
				IssuerVCSPublicHost:     aud,
				JWEEncrypterCreator:     jweEncrypterCreator,
			})

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			if accessToken != "" {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			}

			rec := httptest.NewRecorder()

			err = controller.OidcCredential(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcBatchCredential(t *testing.T) {
	var (
		mockOAuthProvider     = NewMockOAuth2Provider(gomock.NewController(t))
		mockInteractionClient = NewMockIssuerInteractionClient(gomock.NewController(t))
		jweEncrypterCreator   func(jwk gojose.JSONWebKey, alg gojose.KeyAlgorithm, enc gojose.ContentEncryption) (gojose.Encrypter, error) //nolint:lll
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

	signedJWT, err := jwt.NewSigned(&oidc4ci.ProofClaims{
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

	batchCredentialRequest := oidc4ci.BatchCredentialRequest{
		CredentialRequests: []oidc4ci.CredentialRequest{
			{
				Format: lo.ToPtr(string(common.JwtVcJsonLd)),
				CredentialDefinition: &common.CredentialDefinition{
					Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
				},
				Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
			},
			{
				Format: lo.ToPtr(string(common.JwtVcJson)),
				CredentialDefinition: &common.CredentialDefinition{
					Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
				},
				Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
			},
		},
	}

	checkBatchCredentialsResponse := func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)

		var response oidc4ci.BatchCredentialResponse
		err = json.NewDecoder(rec.Body).Decode(&response)

		require.NoError(t, err)

		assert.NotEmpty(t, response.CNonce)
		assert.NotEmpty(t, response.CNonceExpiresIn)
		assert.Len(t, response.CredentialResponses, 2)

		credentialResponseBatchCredential, ok := response.CredentialResponses[0].(map[string]interface{})
		assert.True(t, ok)

		assert.Equal(t, map[string]interface{}{
			"credential":      "credential1 in jwt format",
			"notification_id": "notificationID",
		}, credentialResponseBatchCredential)

		credentialResponseBatchCredential, ok = response.CredentialResponses[1].(map[string]interface{})
		assert.True(t, ok)

		assert.Equal(t, map[string]interface{}{
			"credential":      "credential2 in jwt format",
			"notification_id": "notificationID",
		}, credentialResponseBatchCredential)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	defaultJWEEncrypterCreator := func(jwk gojose.JSONWebKey, alg gojose.KeyAlgorithm, enc gojose.ContentEncryption) (gojose.Encrypter, error) { //nolint:lll
		return gojose.NewEncrypter(
			enc,
			gojose.Recipient{
				Algorithm: alg,
				Key:       jwk,
			},
			nil,
		)
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential:     "credential1 in jwt format",
						Format:         string(verifiable.Jwt),
						NotificationId: "notificationID",
					},
					{
						Credential:     "credential2 in jwt format",
						Format:         string(verifiable.Jwt),
						NotificationId: "notificationID",
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: checkBatchCredentialsResponse,
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential:     "credential1 in jwt format",
						Format:         string(verifiable.Jwt),
						NotificationId: "notificationID",
					},
					{
						Credential:     "credential2 in jwt format",
						Format:         string(verifiable.Jwt),
						NotificationId: "notificationID",
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: checkBatchCredentialsResponse,
		},
		{
			name: "success with one encrypted credential",
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential: "credential1 in jwt format",
						Credentials: []common.CredentialResponseCredentialObject{
							{
								Credential: "credential1 in jwt format",
							},
						},
						Format:         string(verifiable.Jwt),
						NotificationId: "notificationId",
					},
					{
						Credential: "credential2 in jwt format",
						Credentials: []common.CredentialResponseCredentialObject{
							{
								Credential: "credential2 in jwt format",
							},
						},
						Format:         string(verifiable.Jwt),
						NotificationId: "notificationId",
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
							CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
								Alg: string(gojose.ECDH_ES),
								Enc: string(gojose.A128CBC_HS256),
								Jwk: string(b),
							},
						},
						{
							Format: lo.ToPtr(string(common.JwtVcJson)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "PermanentResidentCard"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
						},
					},
				})

				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
				require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

				var response oidc4ci.BatchCredentialResponse
				err = json.NewDecoder(rec.Body).Decode(&response)

				require.NoError(t, err)

				assert.NotEmpty(t, response.CNonce)
				assert.NotEmpty(t, response.CNonceExpiresIn)
				assert.Len(t, response.CredentialResponses, 2)

				credentialResponseBatchCredentialEntrypted, ok := response.CredentialResponses[0].(string)
				assert.True(t, ok)

				jwe, err := gojose.ParseEncrypted(credentialResponseBatchCredentialEntrypted)
				require.NoError(t, err)

				decrypted, err := jwe.Decrypt(ecdsaPrivateKey)
				require.NoError(t, err)

				var resp *oidc4ci.CredentialResponse
				require.NoError(t, json.Unmarshal(decrypted, &resp))

				assert.Equal(t, resp, &oidc4ci.CredentialResponse{
					AcceptanceToken: nil,
					CNonce:          nil,
					CNonceExpiresIn: nil,
					Credential:      "credential1 in jwt format",
					Format:          "",
					NotificationId:  "notificationId",
				})

				credentialResponseBatchCredential, ok := response.CredentialResponses[1].(map[string]interface{})
				assert.True(t, ok)

				assert.Equal(t, credentialResponseBatchCredential, map[string]interface{}{
					"credential":      "credential2 in jwt format",
					"notification_id": "notificationId",
				})
			},
		},
		{
			name: "invalid body",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody = []byte(`{`)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "unexpected EOF")
			},
		},
		{
			name: "credential amount mismatch",
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential: "credential1 in jwt format",
						Format:     string(verifiable.Jwt),
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "credential amount mismatch, requested 2, got 1")
			},
		},
		{
			name: "invalid credential format",
			setup: func() {
				mockOAuthProvider.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), fosite.AccessToken, gomock.Any()).Times(0)
				mockInteractionClient.EXPECT().PrepareCredential(gomock.Any(), gomock.Any()).Times(0)
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr("invalid"),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
						},
					},
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
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: nil,
						},
					},
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
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: nil},
						},
					},
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
				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = ""

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: lo.ToPtr("invalid jws")},
						},
					},
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				var signedJWTInvalid *jwt.JSONWebToken
				signedJWTInvalid, err = jwt.NewSigned(map[string]interface{}{
					"iss": 123,
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, err)

				var jwsInvalid string
				jwsInvalid, err = signedJWTInvalid.Serialize(false)
				require.NoError(t, err)

				credentialReqInvalid := oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jwsInvalid},
						},
					},
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				var signedJWTInvalid *jwt.JSONWebToken
				signedJWTInvalid, err = jwt.NewSigned(&oidc4ci.ProofClaims{
					Issuer:   clientID,
					Nonce:    "c_nonce",
					Audience: aud,
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, err)

				var jwsInvalid string
				jwsInvalid, err = signedJWTInvalid.Serialize(false)
				require.NoError(t, err)

				credentialReqInvalid := oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jwsInvalid},
						},
					},
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "invalid",
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
						},
					},
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "c_nonce",
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any"}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
						},
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				// typ is required per spec
				require.ErrorContains(t, err, "invalid typ")
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				invalidHeaders := map[string]interface{}{
					jose.HeaderType: jwt.TypeJWT,
				}

				currentTime := time.Now().Unix()

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
					Issuer:   clientID,
					Audience: aud,
					IssuedAt: &currentTime,
					Nonce:    "c_nonce",
				}, jwt.SignParameters{JWTAlg: "EdDSA", KeyID: "any", AdditionalHeaders: invalidHeaders}, proofCreator)
				require.NoError(t, jwtErr)

				invalidJWS, marshalErr := invalidNonceJWT.Serialize(false)
				require.NoError(t, marshalErr)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
						},
					},
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).Times(0)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				currentTime := time.Now().Unix()

				invalidNonceJWT, jwtErr := jwt.NewSigned(&oidc4ci.ProofClaims{
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

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &invalidJWS},
						},
					},
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("prepare batch credential error"))

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "prepare batch credential")
			},
		},
		{
			name: "invalid status code in prepare batch credential response (format)",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "oidc-credential-format-not-supported"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "prepare credential: status code 500, {")
			},
		},
		{
			name: "invalid status code in prepare batch credential response (type)",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "oidc-credential-type-not-supported"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err,
					"oidc-error: prepare credential: status code 500, "+
						"code: oidc-credential-type-not-supported")
			},
		},
		{
			name: "invalid status code in prepare batch credential response (random)",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "random", "message": "awesome"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err,
					"prepare credential: status code 500, code: random; message: awesome")
			},
		},
		{
			name: "invalid encryption parameters",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "oidc-invalid-encryption-parameters"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "oidc-invalid-encryption-parameters")
			},
		},
		{
			name: "invalid or missing proof",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "invalid_or_missing_proof", "message": "invalid or missing proof"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var customErr *resterr.CustomError

				assert.ErrorAs(t, err, &customErr)
				assert.ErrorContains(t, customErr, "oidc-error: invalid or missing proof")
				assert.Equal(t, resterr.OIDCError, customErr.Code)
				assert.Equal(t, "invalid_or_missing_proof", customErr.Component)
				assert.Empty(t, customErr.FailedOperation)
			},
		},
		{
			name: "invalid credentials request",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader(`{"code" : "invalid_credential_request"}`)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				var customErr *resterr.CustomError

				assert.ErrorAs(t, err, &customErr)
				assert.ErrorContains(t, customErr, "oidc-error: prepare credential: status code 500, code: invalid_credential_request")
				assert.Equal(t, resterr.OIDCError, customErr.Code)
				assert.Equal(t, "invalid_credential_request", customErr.Component)
				assert.Empty(t, customErr.FailedOperation)
			},
		},
		{
			name: "fail to decode prepare batch credential result",
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

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString("invalid json")),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(batchCredentialRequest)
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "decode prepare credential result")
			},
		},
		{
			name: "fail to unmarshal jwk for encrypting batch credential response",
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential: "credential in jwt format",
						Format:     string(verifiable.Jwt),
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
							CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
								Alg: string(gojose.ECDH_ES),
								Enc: string(gojose.A128CBC_HS256),
								Jwk: "invalid jwk",
							},
						},
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "unmarshal jwk")
			},
		},
		{
			name: "fail to create encrypter for encrypting batch credential response",
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential: "credential in jwt format",
						Format:     string(verifiable.Jwt),
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = defaultJWEEncrypterCreator

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
							CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
								Alg: string(gojose.ED25519),
								Enc: string(gojose.A128CBC_HS256),
								Jwk: string(b),
							},
						},
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "create encrypter")
			},
		},
		{
			name: "fail to encrypt batch credential response",
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential: "credential in jwt format",
						Format:     string(verifiable.Jwt),
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = func(gojose.JSONWebKey, gojose.KeyAlgorithm, gojose.ContentEncryption) (gojose.Encrypter, error) { //nolint:lll,unparam
					return &mockJWEEncrypter{
						Err: errors.New("encrypt error"),
					}, nil
				}

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
							CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
								Alg: string(gojose.ECDH_ES),
								Enc: string(gojose.A128CBC_HS256),
								Jwk: string(b),
							},
						},
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "encrypt credential response")
			},
		},
		{
			name: "fail to serialize encrypted batch credential response",
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

				b, marshalErr := json.Marshal([]issuer.PrepareCredentialResult{
					{
						Credential: "credential in jwt format",
						Format:     string(verifiable.Jwt),
					},
				})
				require.NoError(t, marshalErr)

				mockInteractionClient.EXPECT().PrepareBatchCredential(gomock.Any(), gomock.Any()).
					Return(
						&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBuffer(b)),
						}, nil)

				jweEncrypterCreator = func(gojose.JSONWebKey, gojose.KeyAlgorithm, gojose.ContentEncryption) (gojose.Encrypter, error) { //nolint:lll,unparam
					return &mockJWEEncrypter{
						JWE: &gojose.JSONWebEncryption{},
					}, nil
				}

				accessToken = "access-token"

				jwk := gojose.JSONWebKey{
					Key: &ecdsaPrivateKey.PublicKey,
				}

				b, err = jwk.MarshalJSON()
				require.NoError(t, err)

				requestBody, err = json.Marshal(oidc4ci.BatchCredentialRequest{
					CredentialRequests: []oidc4ci.CredentialRequest{
						{
							Format: lo.ToPtr(string(common.JwtVcJsonLd)),
							CredentialDefinition: &common.CredentialDefinition{
								Type: []string{"VerifiableCredential", "UniversityDegreeCredential"},
							},
							Proof: &oidc4ci.JWTProof{ProofType: "jwt", Jwt: &jws},
							CredentialResponseEncryption: &oidc4ci.CredentialResponseEncryption{
								Alg: string(gojose.ECDH_ES),
								Enc: string(gojose.A128CBC_HS256),
								Jwk: string(b),
							},
						},
					},
				})
				require.NoError(t, err)
			},
			check: func(t *testing.T, rec *httptest.ResponseRecorder, err error) {
				require.ErrorContains(t, err, "serialize credential response")
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
				Tracer:                  nooptracer.NewTracerProvider().Tracer(""),
				IssuerVCSPublicHost:     aud,
				JWEEncrypterCreator:     jweEncrypterCreator,
			})

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(requestBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			if accessToken != "" {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			}

			rec := httptest.NewRecorder()

			err = controller.OidcBatchCredential(echo.New().NewContext(req, rec))
			tt.check(t, rec, err)
		})
	}
}

func TestController_OidcToken_PreAuthorize(t *testing.T) {
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
				ad := getTestOIDCTokenAuthorizationDetailsPayload(t)
				payload := fmt.Sprintf(`{"scopes" : ["a","b"], "op_state" : "opp123", "authorization_details": %s}`, ad)

				mockInteractionClient.EXPECT().ValidatePreAuthorizedCodeRequest(gomock.Any(), gomock.Any()).
					Return(&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(payload)),
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
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				var resp oidc4ci.AccessTokenResponse

				assert.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
				assert.Equal(t, "123456", resp.AccessToken)
				assert.NotEmpty(t, *resp.ExpiresIn)

				ad := *resp.AuthorizationDetails
				assert.Len(t, ad, 1)
				assert.Equal(t, "openid_credential", ad[0].Type)
			},
		},
		{
			name: "name invalid pre-auth code",
			body: strings.NewReader(url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {"123456"},
				"tx_code":             {"5678"},
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
				Tracer:                  nooptracer.NewTracerProvider().Tracer(""),
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

	t.Run("success: with Credentials array", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		expectedToken := "xxxx"

		ackMock.EXPECT().Ack(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, remote oidc4cisrv.AckRemote) error {
				assert.Equal(t, hh(expectedToken), remote.HashedToken)
				assert.Equal(t, "tx_id", string(remote.TxID))
				assert.Equal(t, "credential_accepted", remote.Event)
				assert.Equal(t, "err_txt", remote.EventDescription)
				assert.Equal(t, map[string]interface{}{
					"userId":        "userId",
					"transactionId": "transactionId",
				}, remote.InteractionDetails)

				return nil
			})

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"credentials" : [{"notification_id" : "tx_id", "event" : "credential_accepted", "event_description" : "err_txt"}],
			"interaction_details": {"userId": "userId", "transactionId": "transactionId"}
		}`)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Authorization", "Bearer xxxx")
		rec := httptest.NewRecorder()

		err := controller.OidcAcknowledgement(echo.New().NewContext(req, rec))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("success: without Credentials array", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		expectedToken := "xxxx"

		ackMock.EXPECT().Ack(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, remote oidc4cisrv.AckRemote) error {
				assert.Equal(t, hh(expectedToken), remote.HashedToken)
				assert.Equal(t, "tx_id", string(remote.TxID))
				assert.Equal(t, "credential_accepted", remote.Event)
				assert.Equal(t, "err_txt", remote.EventDescription)
				assert.Equal(t, map[string]interface{}{
					"userId":        "userId",
					"transactionId": "transactionId",
				}, remote.InteractionDetails)

				return nil
			})

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"notification_id": "tx_id", "event": "credential_accepted","event_description": "err_txt",
			"interaction_details": {"userId": "userId", "transactionId": "transactionId"}
		}`)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Authorization", "Bearer xxxx")
		rec := httptest.NewRecorder()

		err := controller.OidcAcknowledgement(echo.New().NewContext(req, rec))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("ack err: with Credentials array", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
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

	t.Run("ack err: without Credentials array", func(t *testing.T) {
		mockOAuthProvider := NewMockOAuth2Provider(gomock.NewController(t))

		ackMock := NewMockAckService(gomock.NewController(t))
		mockOAuthProvider.EXPECT().NewAccessRequest(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&fosite.AccessRequest{}, nil).AnyTimes()
		controller := oidc4ci.NewController(&oidc4ci.Config{
			OAuth2Provider: mockOAuthProvider,
			AckService:     ackMock,
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		ackMock.EXPECT().Ack(gomock.Any(), gomock.Any()).
			Return(errors.New("some error"))

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{
			"notification_id": "tx_id", "event": "credential_accepted","event_description": "err_txt"
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
		})

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{}`)))
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
			Tracer:         nooptracer.NewTracerProvider().Tracer(""),
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
				Tracer:         nooptracer.NewTracerProvider().Tracer(""),
			})

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

			rec := httptest.NewRecorder()

			err := controller.OidcRegisterClient(echo.New().NewContext(req, rec), profileID, profileVersion)
			tt.check(t, rec, err)
		})
	}
}

//go:embed testdata/ldp_proof_2.json
var ldpProofWithTwoProofs []byte

//go:embed testdata/ldp_proof_invalid_date.json
var ldpProofWithInvalidDate []byte

func TestHandleLDPProof(t *testing.T) {
	t.Run("invalid proof", func(t *testing.T) {
		ctr := oidc4ci.NewController(&oidc4ci.Config{})
		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "ldp_vp",
				LdpVp:     nil,
			},
		}, nil)
		assert.ErrorContains(t, err, "missing ldp_vp")
	})

	t.Run("proof parse err", func(t *testing.T) {
		var finalPres map[string]interface{}
		require.NoError(t, json.Unmarshal(ldpProofContent, &finalPres))
		ldpParser := NewMockLDPProofParser(gomock.NewController(t))
		ctr := oidc4ci.NewController(&oidc4ci.Config{
			LDPProofParser: ldpParser,
		})

		ldpParser.EXPECT().Parse(gomock.Any(), gomock.Any()).Return(nil, errors.New("parse error"))

		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "ldp_vp",
				LdpVp:     &finalPres,
			},
		}, nil)
		assert.ErrorContains(t, err, "can not parse ldp_vp as presentation")
	})

	t.Run("invalid proof count", func(t *testing.T) {
		var finalPres map[string]interface{}
		require.NoError(t, json.Unmarshal(ldpProofContent, &finalPres))
		ldpParser := NewMockLDPProofParser(gomock.NewController(t))
		ctr := oidc4ci.NewController(&oidc4ci.Config{
			LDPProofParser: ldpParser,
		})

		ldpParser.EXPECT().Parse(gomock.Any(), gomock.Any()).
			DoAndReturn(func(i []byte, opts []verifiable2.PresentationOpt) (*verifiable2.Presentation, error) {
				return verifiable2.ParsePresentation(ldpProofWithTwoProofs,
					verifiable2.WithPresDisabledProofCheck(),
					verifiable2.WithDisabledJSONLDChecks())
			})

		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "ldp_vp",
				LdpVp:     &finalPres,
			},
		}, nil)
		assert.ErrorContains(t, err, "expected 1 proof, got 2")
	})

	t.Run("invalid date", func(t *testing.T) {
		var finalPres map[string]interface{}
		require.NoError(t, json.Unmarshal(ldpProofContent, &finalPres))
		ldpParser := NewMockLDPProofParser(gomock.NewController(t))
		ctr := oidc4ci.NewController(&oidc4ci.Config{
			LDPProofParser: ldpParser,
		})

		ldpParser.EXPECT().Parse(gomock.Any(), gomock.Any()).
			DoAndReturn(func(i []byte, opts []verifiable2.PresentationOpt) (*verifiable2.Presentation, error) {
				return verifiable2.ParsePresentation(ldpProofWithInvalidDate,
					verifiable2.WithPresDisabledProofCheck(),
					verifiable2.WithDisabledJSONLDChecks())
			})

		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "ldp_vp",
				LdpVp:     &finalPres,
			},
		}, nil)
		assert.ErrorContains(t, err, "oidc-error: parse created: parsing time")
	})
}

func TestHandleCWTProof(t *testing.T) {
	exampleProof := "d28458cba301260378206170706c69636174696f6e2f6f70656e6964347663692d70726f6f662b63777468434f53455f4b6579789a61353031303230333236323030313231353832303234646635303465613637346532626339663536303962363962373533636430336566333036626265316636356466643566363037393139376234626635363632323538323064303666316532346537313330343561373938376337343462313266383438663665323737376132396537346637316231363039633334343832333237313336a05842a40a746b596362437876656c6531706e393459704b6a44016b746573742d636c69656e740376687474703a2f2f3132372e302e302e313a3630343133061a65ba47ef590233d28458cba301260378206170706c69636174696f6e2f6f70656e6964347663692d70726f6f662b63777468434f53455f4b6579789a61353031303230333236323030313231353832303234646635303465613637346532626339663536303962363962373533636430336566333036626265316636356466643566363037393139376234626635363632323538323064303666316532346537313330343561373938376337343462313266383438663665323737376132396537346637316231363039633334343832333237313336a059011e846a5369676e61747572653158cba301260378206170706c69636174696f6e2f6f70656e6964347663692d70726f6f662b63777468434f53455f4b6579789a61353031303230333236323030313231353832303234646635303465613637346532626339663536303962363962373533636430336566333036626265316636356466643566363037393139376234626635363632323538323064303666316532346537313330343561373938376337343462313266383438663665323737376132396537346637316231363039633334343832333237313336405842a40a746b596362437876656c6531706e393459704b6a44016b746573742d636c69656e740376687474703a2f2f3132372e302e302e313a3630343133061a65ba47ef5840e473533ec03037ea07f933b57d845bcdd9731830ca74a4cc29fb201e5b41030f46fdebac6f076cef8c9b2abecee5ff996682b57a3c55db49945ee200942a831a" //nolint
	hexProof, err := hex.DecodeString(exampleProof)
	require.NoError(t, err)

	t.Run("invalid string", func(t *testing.T) {
		ctr := oidc4ci.NewController(&oidc4ci.Config{})
		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "cwt",
				Cwt:       lo.ToPtr("0xxx0"),
			},
		}, nil)
		assert.ErrorContains(t, err, "invalid cwt")
	})

	t.Run("invalid cwt content", func(t *testing.T) {
		verifier := NewMockCwtProofChecker(gomock.NewController(t))
		ctr := oidc4ci.NewController(&oidc4ci.Config{
			CWTVerifier: verifier,
		})

		verifier.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errors.New("unexpected cwt error"))
		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "cwt",
				Cwt:       &exampleProof,
			},
		}, nil)
		assert.ErrorContains(t, err, "unexpected cwt error")
	})

	t.Run("invalid proof claims", func(t *testing.T) {
		verifier := NewMockCwtProofChecker(gomock.NewController(t))
		ctr := oidc4ci.NewController(&oidc4ci.Config{
			CWTVerifier: verifier,
		})

		var data cose.Sign1Message
		assert.NoError(t, cbor.Unmarshal(hexProof, &data))

		data.Payload = []byte{0x1, 0x2}
		proof, cErr := cbor.Marshal(data)
		require.NoError(t, cErr)

		verifier.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)
		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "cwt",
				Cwt:       lo.ToPtr(hex.EncodeToString(proof)),
			},
		}, nil)
		assert.ErrorContains(t, err, "invalid cwt claims")
	})

	t.Run("invalid content type", func(t *testing.T) {
		verifier := NewMockCwtProofChecker(gomock.NewController(t))
		ctr := oidc4ci.NewController(&oidc4ci.Config{
			CWTVerifier: verifier,
		})

		var data *cose.Sign1Message
		assert.NoError(t, cbor.Unmarshal(hexProof, &data))

		delete(data.Headers.Protected, cose.HeaderLabelContentType)
		b, _ := data.Headers.Protected.MarshalCBOR()
		data.Headers.RawProtected = b

		proof, cErr := cbor.Marshal(data)
		require.NoError(t, cErr)

		verifier.EXPECT().CheckCWTProof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)
		_, _, err := ctr.HandleProof("invalid", &oidc4ci.CredentialRequest{
			Proof: &oidc4ci.JWTProof{
				ProofType: "cwt",
				Cwt:       lo.ToPtr(hex.EncodeToString(proof)),
			},
		}, nil)
		assert.ErrorContains(t, err, "invalid COSE content type")
	})
}

type mockJWEEncrypter struct {
	JWE *gojose.JSONWebEncryption
	Err error
}

func (m *mockJWEEncrypter) Encrypt([]byte) (*gojose.JSONWebEncryption, error) {
	return m.JWE, m.Err
}

func (m *mockJWEEncrypter) EncryptWithAuthData([]byte, []byte) (*gojose.JSONWebEncryption, error) {
	return &gojose.JSONWebEncryption{}, nil
}

func (m *mockJWEEncrypter) Options() gojose.EncrypterOptions {
	return gojose.EncrypterOptions{}
}

func getTestOIDCTokenAuthorizationDetailsPayload(t *testing.T) string {
	t.Helper()

	res := &issuecredential.AuthorizationDetails{
		CredentialConfigurationID: "CredentialConfigurationID",
		Locations:                 []string{"https://example.com/rs1", "https://example.com/rs2"},
		Type:                      "openid_credential",
		CredentialDefinition: &issuecredential.CredentialDefinition{
			Context:           []string{"https://example.com/context/1", "https://example.com/context/2"},
			CredentialSubject: map[string]interface{}{"key": "value"},
			Type:              []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
		Format:                "jwt",
		CredentialIdentifiers: []string{"CredentialIdentifiers1", "CredentialIdentifiers2"},
	}

	payload := []common.AuthorizationDetails{res.ToDTO()}

	b, err := json.Marshal(payload)
	assert.NoError(t, err)

	return string(b)
}
