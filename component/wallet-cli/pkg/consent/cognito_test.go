/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package consent_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/consent"
)

func TestCognitoConsent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		statusCodes := []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther}
		for _, code := range statusCodes {
			t.Run(fmt.Sprintf("verify with status code %v", code), func(t *testing.T) {
				cl := NewMockhttpClient(gomock.NewController(t))

				targetURL := "https://example.auth.us-east-2.amazoncognito.com/login?client_id=example&redirect_uri=" +
					"https%3A%2F%2Fexample-redirect.com%2Fvcs%2Foidc%2Fredirect&response_type=code&" +
					"state=9bc93ec1-7bdd-4084-8948-299ef35adab8"

				ct := consent.NewCognito(
					cl,
					[]*http.Cookie{
						{
							Name:  "XSRF-TOKEN",
							Value: "abcd",
						},
					},
					targetURL,
					"some-login",
					"some-password",
				)

				cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
					assert.Equal(t, http.MethodGet, request.Method)
					assert.Equal(t, targetURL, request.URL.String())

					return &http.Response{
						Header: map[string][]string{
							"Set-Cookie": {
								"XSRF-TOKEN=8f6cafbe-34c3-4c96-b53b-47c798297e79; Path=/; Secure; HttpOnly; SameSite=Lax",
							},
						},
					}, nil
				})

				cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
					assert.Equal(t, http.MethodPost, request.Method)
					assert.Equal(t, targetURL, request.URL.String())
					assert.Equal(t, "XSRF-TOKEN", request.Cookies()[0].Name)
					assert.Equal(t, "8f6cafbe-34c3-4c96-b53b-47c798297e79", request.Cookies()[0].Value)
					assert.NoError(t, request.ParseForm())

					assert.Equal(t, "some-login", request.Form.Get("username"))
					assert.Equal(t, "Sign in", request.Form.Get("signInSubmitButton"))
					assert.Equal(t, "some-password", request.Form.Get("password"))
					assert.Equal(t, "8f6cafbe-34c3-4c96-b53b-47c798297e79", request.Form.Get("_csrf"))
					return &http.Response{
						StatusCode: code,
					}, nil
				})

				assert.NoError(t, ct.Execute())
			})
		}
	})

	t.Run("fail get", func(t *testing.T) {
		cl := NewMockhttpClient(gomock.NewController(t))

		targetURL := "https://example.auth.us-east-2.amazoncognito.com/login?client_id=example&redirect_uri=https%3A%" +
			"2F%2Fexample-redirect.com%2Fvcs%2Foidc%2Fredirect&response_type=code&" +
			"state=9bc93ec1-7bdd-4084-8948-299ef35adab8"

		ct := consent.NewCognito(
			cl,
			[]*http.Cookie{
				{
					Name:  "XSRF-TOKEN",
					Value: "abcd",
				},
			},
			targetURL,
			"some-login",
			"some-password",
		)

		cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
			assert.Equal(t, http.MethodGet, request.Method)
			assert.Equal(t, targetURL, request.URL.String())

			return nil, errors.New("some error")
		})

		assert.ErrorContains(t, ct.Execute(), "some error")
	})

	t.Run("missing csrf", func(t *testing.T) {
		cl := NewMockhttpClient(gomock.NewController(t))

		targetURL := "https://example.auth.us-east-2.amazoncognito.com/login?client_id=example&redirect_uri=https%3A%" +
			"2F%2Fexample-redirect.com%2Fvcs%2Foidc%2Fredirect&response_type=code&" +
			"state=9bc93ec1-7bdd-4084-8948-299ef35adab8"

		ct := consent.NewCognito(
			cl,
			nil,
			targetURL,
			"some-login",
			"some-password",
		)

		cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
			return &http.Response{}, nil
		})

		assert.ErrorContains(t, ct.Execute(), "XSRF-TOKEN cookie not found")
	})

	t.Run("fail post", func(t *testing.T) {
		cl := NewMockhttpClient(gomock.NewController(t))

		targetURL := "https://example.auth.us-east-2.amazoncognito.com/login?client_id=example&redirect_uri=https%3A%" +
			"2F%2Fexample-redirect.com%2Fvcs%2Foidc%2Fredirect&response_type=code&" +
			"state=9bc93ec1-7bdd-4084-8948-299ef35adab8"

		ct := consent.NewCognito(
			cl,
			[]*http.Cookie{
				{
					Name:  "XSRF-TOKEN",
					Value: "abcd",
				},
			},
			targetURL,
			"some-login",
			"some-password",
		)

		cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
			return &http.Response{}, nil
		})

		cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
			return nil, errors.New("post failed")
		})

		assert.ErrorContains(t, ct.Execute(), "post failed")
	})

	t.Run("fail invalid status code", func(t *testing.T) {
		cl := NewMockhttpClient(gomock.NewController(t))

		targetURL := "https://example.auth.us-east-2.amazoncognito.com/login?client_id=example&redirect_uri=https%3A%" +
			"2F%2Fexample-redirect.com%2Fvcs%2Foidc%2Fredirect&response_type=code&" +
			"state=9bc93ec1-7bdd-4084-8948-299ef35adab8"

		ct := consent.NewCognito(
			cl,
			[]*http.Cookie{
				{
					Name:  "XSRF-TOKEN",
					Value: "abcd",
				},
			},
			targetURL,
			"some-login",
			"some-password",
		)

		cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
			return &http.Response{}, nil
		})

		cl.EXPECT().Do(gomock.Any()).DoAndReturn(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusMultiStatus,
				Body:       io.NopCloser(strings.NewReader(`some random text`)),
			}, nil
		})

		assert.ErrorContains(t, ct.Execute(), "unexpected status code from post cognito. 207 with body some random text")
	})
}
