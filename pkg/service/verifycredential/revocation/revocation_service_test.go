/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package revocation

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	vdr2 "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

type mockHTTPClient struct {
	doValue *http.Response
	doErr   error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.doValue, m.doErr
}

func TestNew(t *testing.T) {
	type args struct {
		config *Config
	}
	tests := []struct {
		name string
		args args
		want *Service
	}{
		{
			name: "OK",
			args: args{
				config: &Config{
					VDR: &vdrmock.MockVDRegistry{},
					TLSConfig: &tls.Config{
						MinVersion: tls.VersionTLS12,
						RootCAs:    x509.NewCertPool(),
					},
					RequestTokens:  map[string]string{"abc": "123"},
					DocumentLoader: testutil.DocumentLoader(t),
				},
			},
			want: &Service{
				vdr: &vdrmock.MockVDRegistry{},
				httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    x509.NewCertPool(),
				}}},
				requestTokens:  map[string]string{"abc": "123"},
				documentLoader: testutil.DocumentLoader(t),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_GetRevocationListVC(t *testing.T) {
	loader := testutil.DocumentLoader(t)
	// Assert
	vc, err := verifiable.ParseCredential(
		[]byte(sampleVCJWT),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	type fields struct {
		getVdr         func() vdr.Registry
		httpClient     httpClient
		documentLoader ld.DocumentLoader
	}
	type args struct {
		statusURL string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiable.Credential
		wantErr bool
	}{
		{
			name: "OK HTTP",
			fields: fields{
				getVdr: func() vdr.Registry {
					universalResolverVDRI, err := httpbinding.New("https://uniresolver.io/1.0/identifiers",
						httpbinding.WithAccept(func(method string) bool { return method == "ion" }))
					require.NoError(t, err)

					return vdr2.New(vdr2.WithVDR(universalResolverVDRI))
				},
				httpClient: &mockHTTPClient{
					doValue: &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(sampleVCJWT))),
					},
					doErr: nil,
				},
				documentLoader: loader,
			},
			args: args{
				statusURL: "https://example.com/credentials/status/1",
			},
			want:    vc,
			wantErr: false,
		},
		{
			name: "OK DID",
			fields: fields{
				getVdr: func() vdr.Registry {
					universalResolverVDRI, err := httpbinding.New("https://uniresolver.io/1.0/identifiers",
						httpbinding.WithAccept(func(method string) bool { return method == "ion" }))
					require.NoError(t, err)

					return vdr2.New(vdr2.WithVDR(universalResolverVDRI))
				},
				httpClient:     http.DefaultClient,
				documentLoader: loader,
			},
			args: args{
				statusURL: didRelativeURL,
			},
			want:    vc,
			wantErr: false,
		},
		{
			name: "NewRequestWithContext URL starts with space Error",
			fields: fields{
				getVdr: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{}
				},
			},
			args: args{
				statusURL: " https://example.com/credentials/status/1",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "sendHTTPRequest Error",
			fields: fields{
				httpClient: &mockHTTPClient{
					doErr: errors.New("some error"),
				},
				getVdr: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{}
				},
			},
			args: args{
				statusURL: "https://example.com/credentials/status/1",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "sendHTTPRequest Invalid status code",
			fields: fields{
				getVdr: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{}
				},
				httpClient: &mockHTTPClient{
					doValue: &http.Response{
						StatusCode: http.StatusForbidden,
						Body:       io.NopCloser(bytes.NewReader([]byte(sampleVCJWT))),
					},
					doErr: nil,
				},
			},
			args: args{
				statusURL: "https://example.com/credentials/status/1",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "parseAndVerifyVC Error",
			fields: fields{
				getVdr: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{}
				},
				httpClient: &mockHTTPClient{
					doValue: &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(""))),
					},
					doErr: nil,
				},
				documentLoader: loader,
			},
			args: args{
				statusURL: "https://example.com/credentials/status/1",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:            tt.fields.getVdr(),
				httpClient:     tt.fields.httpClient,
				documentLoader: tt.fields.documentLoader,
				requestTokens: map[string]string{
					cslRequestTokenName: "abc",
				},
			}
			got, err := s.GetRevocationVC(tt.args.statusURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRevocationListVC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRevocationListVC() got = %v, want %v", got, tt.want)
			}
		})
	}
}
