package privateapi_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/component/privateapi"
)

func TestPrepareClaimDataAuthZ(t *testing.T) {
	hostURL := "https://127.0.0.1"
	cl := NewMockHttpClient(gomock.NewController(t))

	finalRedirectURL := "https://truest.com/redirect?q=23"

	redirectURI, err := url.Parse("https://trust.com/path?qwery=123")
	assert.NoError(t, err)

	opState := uuid.NewString()
	req := &privateapi.PrepareClaimDataAuthZRequest{
		OpState: opState,
		Responder: privateapi.PrepareClaimResponder{
			RedirectURI: redirectURI,
			RespondMode: "random_respond_mode",
			AuthorizeResponse: fosite.AuthorizeResponse{
				Header: http.Header{
					"header1": []string{"value", "value2"},
				},
				Parameters: redirectURI.Query(),
			},
		},
	}

	cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "/issuer/interactions/prepare-claim-data-authz-request", req.URL.RequestURI())
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("{\"redirect_uri\" : \"%v\"}", finalRedirectURL))),
		}, nil
	})

	api := privateapi.NewClient(
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

	api := privateapi.NewClient(
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

	api := privateapi.NewClient(
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

	api := privateapi.NewClient(
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
