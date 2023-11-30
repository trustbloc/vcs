/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientattestation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
)

func TestService_doTrustRegistryRequest(t *testing.T) {
	handler := echo.New()

	srv := httptest.NewServer(handler)
	defer srv.Close()

	var reqBody []byte
	var client httpClient

	tests := []struct {
		name  string
		url   string
		setup func(t *testing.T)
		check func(t *testing.T, trResponse *TrustRegistryResponse, err error)
	}{
		{
			name: "Success",
			url:  srv.URL + "/testcase1",
			setup: func(t *testing.T) {
				b, err := json.Marshal(map[string]string{"key": "value"})
				assert.NoError(t, err)

				reqBody = b
				client = http.DefaultClient

				handler.Add(http.MethodPost, "/testcase1", func(c echo.Context) error {
					assert.Equal(t, "application/json", c.Request().Header.Get("content-type"))

					var got map[string]string
					assert.NoError(t, c.Bind(&got))
					assert.Equal(t, map[string]string{"key": "value"}, got)

					return c.JSON(http.StatusOK, map[string]bool{"allowed": true})
				})
			},
			check: func(t *testing.T, trResponse *TrustRegistryResponse, err error) {
				assert.NoError(t, err)
				assert.Equal(t, &TrustRegistryResponse{Allowed: true}, trResponse)
			},
		},
		{
			name: "Error create request",
			url:  "   https://example.com",
			setup: func(t *testing.T) {
				client = &mockHTTPClient{}
			},
			check: func(t *testing.T, trResponse *TrustRegistryResponse, err error) {
				assert.ErrorContains(t, err, "create request")
				assert.Nil(t, trResponse)
			},
		},
		{
			name: "Error do request",
			url:  srv.URL + "/testcase1",
			setup: func(t *testing.T) {
				client = &mockHTTPClient{}
			},
			check: func(t *testing.T, trResponse *TrustRegistryResponse, err error) {
				assert.ErrorContains(t, err, "send request: some error")
				assert.Nil(t, trResponse)
			},
		},
		{
			name: "Error unexpected status code",
			url:  srv.URL + "/testcase2",
			setup: func(t *testing.T) {
				client = http.DefaultClient

				handler.Add(http.MethodPost, "/testcase2", func(c echo.Context) error {
					return c.NoContent(http.StatusBadRequest)
				})
			},
			check: func(t *testing.T, trResponse *TrustRegistryResponse, err error) {
				assert.ErrorContains(t, err, "unexpected status code")
				assert.Nil(t, trResponse)
			},
		},
		{
			name: "Error invalid response structure",
			url:  srv.URL + "/testcase3",
			setup: func(t *testing.T) {
				client = http.DefaultClient

				handler.Add(http.MethodPost, "/testcase3", func(c echo.Context) error {
					assert.Equal(t, "application/json", c.Request().Header.Get("content-type"))

					return c.JSON(http.StatusOK, map[string]string{"allowed": "true"})
				})
			},
			check: func(t *testing.T, trResponse *TrustRegistryResponse, err error) {
				assert.ErrorContains(t, err, "read response")
				assert.Nil(t, trResponse)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			rsp, err := (&Service{
				httpClient: client,
			}).doTrustRegistryRequest(context.Background(), tt.url, reqBody)

			tt.check(t, rsp, err)
		})
	}
}

type mockHTTPClient struct {
}

func (c *mockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("some error")
}

func Test_getCredentialMetadata(t *testing.T) {
	now := time.Now()

	type args struct {
		content verifiable.CredentialContents
	}
	tests := []struct {
		name string
		args args
		want *CredentialMetadata
	}{
		{
			name: "Success",
			args: args{
				content: verifiable.CredentialContents{
					ID:      "credentialID",
					Types:   []string{verifiable.VCType, "WalletAttestationCredential"},
					Issuer:  &verifiable.Issuer{ID: "someIssuerID"},
					Issued:  nil,
					Expired: nil,
				},
			},
			want: &CredentialMetadata{
				CredentialID: "credentialID",
				Types:        []string{verifiable.VCType, "WalletAttestationCredential"},
				IssuerID:     "someIssuerID",
				Issued:       "",
				Expired:      "",
			},
		},
		{
			name: "Success with iss and exp",
			args: args{
				content: verifiable.CredentialContents{
					ID:     "credentialID",
					Types:  []string{verifiable.VCType, "WalletAttestationCredential"},
					Issuer: &verifiable.Issuer{ID: "someIssuerID"},
					Issued: &utiltime.TimeWrapper{
						Time: now,
					},
					Expired: &utiltime.TimeWrapper{
						Time: now.Add(time.Hour),
					},
				},
			},
			want: &CredentialMetadata{
				CredentialID: "credentialID",
				Types:        []string{verifiable.VCType, "WalletAttestationCredential"},
				IssuerID:     "someIssuerID",
				Issued:       now.Format(time.RFC3339Nano),
				Expired:      now.Add(time.Hour).Format(time.RFC3339Nano),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getCredentialMetadata(tt.args.content)
			assert.Equalf(t, tt.want, actual, "getCredentialMetadata(%v)", tt.args.content)
		})
	}
}
