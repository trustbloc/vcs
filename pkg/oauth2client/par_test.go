/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/trustbloc/vcs/pkg/oauth2client"
)

func TestParSuccess(t *testing.T) {
	cl := oauth2client.NewOAuth2Client()
	roundTripper := NewMockHttpRoundTripper(gomock.NewController(t))

	parEndpoint := "https://localhost/par"
	state := "my-awesome-state"
	httpClient := &http.Client{
		Transport: roundTripper,
	}

	roundTripper.EXPECT().RoundTrip(gomock.Any()).
		DoAndReturn(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "POST", req.Method)
			assert.NoError(t, req.ParseForm())
			assert.Equal(t, "value1", req.FormValue("test1"))
			assert.Equal(t, "value2", req.FormValue("test2"))
			assert.Equal(t, "code", req.FormValue("response_type"))
			assert.Equal(t, state, req.FormValue("state"))
			assert.Equal(t, "abcd1234", req.FormValue("client_id"))
			assert.Equal(t, "https://my-redirect/redirect", req.FormValue("redirect_uri"))
			assert.Equal(t, "a b", req.FormValue("scope"))

			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader(`{"request_uri" : "ie:2133241:bvxz", "expires_in" : 60}`)),
			}, nil
		})

	authURL, err := cl.AuthCodeURLWithPAR(context.TODO(), oauth2.Config{
		ClientID:    "abcd1234",
		RedirectURL: "https://my-redirect/redirect",
		Scopes:      []string{"a", "b"},
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://localhost/authorize",
		},
	}, parEndpoint, state, httpClient,
		oauth2client.SetAuthURLParam("test1", "value1"),
		oauth2client.SetAuthURLParam("test2", "value2"),
	)

	assert.NoError(t, err)
	assert.Equal(t, "https://localhost/authorize?client_id=abcd1234&request_uri=ie%3A2133241%3Abvxz", authURL)
}

func TestParFail(t *testing.T) {
	cl := oauth2client.NewOAuth2Client()

	t.Run("http error", func(t *testing.T) {
		roundTripper := NewMockHttpRoundTripper(gomock.NewController(t))
		roundTripper.EXPECT().RoundTrip(gomock.Any()).
			Return(nil, errors.New("http error"))

		authURL, err := cl.AuthCodeURLWithPAR(context.TODO(), oauth2.Config{}, "https://localhost", "",
			&http.Client{
				Transport: roundTripper,
			},
		)
		assert.Empty(t, authURL)
		assert.ErrorContains(t, err, "http error")
	})

	t.Run("http invalid status", func(t *testing.T) {
		roundTripper := NewMockHttpRoundTripper(gomock.NewController(t))
		roundTripper.EXPECT().RoundTrip(gomock.Any()).
			Return(&http.Response{
				StatusCode: http.StatusInternalServerError,
			}, nil)

		authURL, err := cl.AuthCodeURLWithPAR(context.TODO(), oauth2.Config{}, "https://localhost", "",
			&http.Client{
				Transport: roundTripper,
			},
		)
		assert.Empty(t, authURL)
		assert.ErrorContains(t, err, "unexpected status code 500")
	})

	t.Run("http invalid json", func(t *testing.T) {
		roundTripper := NewMockHttpRoundTripper(gomock.NewController(t))
		roundTripper.EXPECT().RoundTrip(gomock.Any()).
			Return(&http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader("{")),
			}, nil)

		authURL, err := cl.AuthCodeURLWithPAR(context.TODO(), oauth2.Config{}, "https://localhost", "",
			&http.Client{
				Transport: roundTripper,
			},
		)
		assert.Empty(t, authURL)
		assert.ErrorContains(t, err, "unexpected EOF")
	})
}
