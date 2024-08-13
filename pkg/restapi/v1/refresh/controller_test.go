/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/refresh"
	refresh2 "github.com/trustbloc/vcs/pkg/service/refresh"
)

const (
	orgID          = "orgID1"
	profileID      = "testID"
	profileVersion = "v1.0"
)

func TestGetRefreshStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		profileSvc := NewMockProfileService(gomock.NewController(t))
		refreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		echoCtx := echoContext(
			withRecorder(recorder),
		)

		echoCtx.Request().URL.Path = "/refresh/" + profileID + "/" + profileVersion

		issuer := &profileapi.Issuer{}
		profileSvc.EXPECT().GetProfile(profileID, profileVersion).
			Return(issuer, nil)

		refreshSvc.EXPECT().RequestRefreshStatus(gomock.Any(), "some-cred-id", *issuer).
			Return(&refresh2.GetRefreshStateResponse{
				Challenge: "challenge",
				Domain:    "domain",
				RefreshServiceType: refresh2.ServiceType{
					Type: "someType",
					URL:  "someURL",
				},
			}, nil)

		ctr := refresh.NewController(&refresh.Config{
			ProfileService:      profileSvc,
			RefreshService:      refreshSvc,
			IssuerVCSPublicHost: "https://public.local/api/vc",
		})

		assert.NoError(t, ctr.RequestRefreshStatus(echoCtx, profileID, profileVersion, refresh.RequestRefreshStatusParams{
			CredentialID: "some-cred-id",
		}))

		var res refresh.CredentialRefreshAvailableResponse
		assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &res))

		assert.Equal(t, "challenge", res.VerifiablePresentationRequest.Challenge)
		assert.Equal(t, "domain", res.VerifiablePresentationRequest.Domain)

		assert.Len(t, res.VerifiablePresentationRequest.Interact.Service, 1)
		assert.Equal(t, "someType", res.VerifiablePresentationRequest.Interact.Service[0].Type)
		assert.Equal(t, "https://public.local/api/vc/refresh/testID/v1.0",
			res.VerifiablePresentationRequest.Interact.Service[0].ServiceEndpoint)

		assert.EqualValues(t, recorder.Result().StatusCode, http.StatusOK)
	})

	t.Run("no updates", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		profileSvc := NewMockProfileService(gomock.NewController(t))
		refreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		echoCtx := echoContext(
			withRecorder(recorder),
		)

		echoCtx.Request().URL.Path = "/refresh/" + profileID + "/" + profileVersion

		issuer := &profileapi.Issuer{}
		profileSvc.EXPECT().GetProfile(profileID, profileVersion).
			Return(issuer, nil)

		refreshSvc.EXPECT().RequestRefreshStatus(gomock.Any(), "some-cred-id", *issuer).
			Return(nil, nil)

		ctr := refresh.NewController(&refresh.Config{
			ProfileService:      profileSvc,
			RefreshService:      refreshSvc,
			IssuerVCSPublicHost: "https://public.local/api/vc",
		})

		assert.NoError(t, ctr.RequestRefreshStatus(echoCtx, profileID, profileVersion, refresh.RequestRefreshStatusParams{
			CredentialID: "some-cred-id",
		}))

		assert.EqualValues(t, recorder.Result().StatusCode, http.StatusNoContent)
	})

	t.Run("refresh err", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		profileSvc := NewMockProfileService(gomock.NewController(t))
		refreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		echoCtx := echoContext(
			withRecorder(recorder),
		)

		echoCtx.Request().URL.Path = "/refresh/" + profileID + "/" + profileVersion

		issuer := &profileapi.Issuer{}
		profileSvc.EXPECT().GetProfile(profileID, profileVersion).
			Return(issuer, nil)

		refreshSvc.EXPECT().RequestRefreshStatus(gomock.Any(), "some-cred-id", *issuer).
			Return(nil, errors.New("refresh err"))

		ctr := refresh.NewController(&refresh.Config{
			ProfileService:      profileSvc,
			RefreshService:      refreshSvc,
			IssuerVCSPublicHost: "https://public.local/api/vc",
		})

		assert.ErrorContains(t, ctr.RequestRefreshStatus(echoCtx, profileID, profileVersion, refresh.RequestRefreshStatusParams{
			CredentialID: "some-cred-id",
		}), "refresh err")
	})

	t.Run("profile err", func(t *testing.T) {
		recorder := httptest.NewRecorder()

		profileSvc := NewMockProfileService(gomock.NewController(t))
		refreshSvc := NewMockCredentialRefreshService(gomock.NewController(t))

		echoCtx := echoContext(
			withRecorder(recorder),
		)

		echoCtx.Request().URL.Path = "/refresh/" + profileID + "/" + profileVersion

		profileSvc.EXPECT().GetProfile(profileID, profileVersion).
			Return(nil, errors.New("profile err"))

		ctr := refresh.NewController(&refresh.Config{
			ProfileService:      profileSvc,
			RefreshService:      refreshSvc,
			IssuerVCSPublicHost: "https://public.local/api/vc",
		})

		assert.ErrorContains(t, ctr.RequestRefreshStatus(echoCtx, profileID, profileVersion, refresh.RequestRefreshStatusParams{
			CredentialID: "some-cred-id",
		}), "profile err")
	})
}

type options struct {
	tenantID       string
	requestBody    []byte
	responseWriter http.ResponseWriter
}

type contextOpt func(*options)

func withTenantID(tenantID string) contextOpt {
	return func(o *options) {
		o.tenantID = tenantID
	}
}

func withRequestBody(body []byte) contextOpt {
	return func(o *options) {
		o.requestBody = body
	}
}

func withRecorder(w http.ResponseWriter) contextOpt {
	return func(o *options) {
		o.responseWriter = w
	}
}

func echoContext(opts ...contextOpt) echo.Context {
	o := &options{
		tenantID:       orgID,
		responseWriter: httptest.NewRecorder(),
	}

	for _, fn := range opts {
		fn(o)
	}

	e := echo.New()

	var body io.Reader = http.NoBody

	if o.requestBody != nil {
		body = bytes.NewReader(o.requestBody)
	}

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	if o.tenantID != "" {
		req.Header.Set("X-Tenant-ID", o.tenantID)
	}

	return e.NewContext(req, o.responseWriter)
}
