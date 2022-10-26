/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapiclient_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/restapiclient"
)

func TestPrepareClaimDataAuthZ(t *testing.T) {
	hostURL := "https://127.0.0.1"
	cl := NewMockHttpClient(gomock.NewController(t))

	finalRedirectURL := "https://truest.com/redirect?q=23"

	opState := uuid.NewString()
	req := &restapiclient.PrepareClaimDataAuthorizationRequest{
		OpState: opState,
	}

	cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "/issuer/interactions/prepare-claim-data-authz-request", req.URL.RequestURI())
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("{\"redirect_uri\" : \"%v\"}", finalRedirectURL))),
		}, nil
	})

	api := restapiclient.NewClient(
		hostURL,
		cl,
	)

	resp, err := api.PrepareClaimDataAuthZ(context.TODO(), req)
	assert.NoError(t, err)
	assert.Equal(t, finalRedirectURL, resp.RedirectURI)
}

func TestWithoutMarshal(t *testing.T) {
	cl := NewMockHttpClient(gomock.NewController(t))
	errStr := "sending err"

	api := restapiclient.NewClient(
		"https://rand",
		cl,
	)

	cl.EXPECT().Do(gomock.Any()).Return(nil, errors.New(errStr))

	resp, err := api.PrepareClaimDataAuthZ(context.TODO(), nil)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, errStr)
}

func TestInvalidStatusCode(t *testing.T) {
	cl := NewMockHttpClient(gomock.NewController(t))

	api := restapiclient.NewClient(
		"https://rand",
		cl,
	)

	cl.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusBadRequest,
	}, nil)

	resp, err := api.PrepareClaimDataAuthZ(context.TODO(), nil)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "unexpected status code 400")
}

func TestWithUnMarshalErr(t *testing.T) {
	cl := NewMockHttpClient(gomock.NewController(t))

	api := restapiclient.NewClient(
		"https://rand",
		cl,
	)

	cl.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{")),
	}, nil)

	resp, err := api.PrepareClaimDataAuthZ(context.TODO(), nil)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "unexpected end of JSON input")
}
