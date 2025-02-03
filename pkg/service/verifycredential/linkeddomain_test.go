/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifycredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/doc/did/endpoint"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	vdrmock "github.com/trustbloc/did-go/vdr/mock"

	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

const (
	testDID = "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"

	contextV1 = "https://identity.foundation/.well-known/did-configuration/v1"

	//nolint:lll
	didCfgCtxV1 = `
{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "LinkedDomains": "https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains",
      "DomainLinkageCredential": "https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential",
      "origin": "https://identity.foundation/.well-known/resources/did-configuration/#origin",
      "linked_dids": "https://identity.foundation/.well-known/resources/did-configuration/#linked_dids"
    }
  ]
}`
	//nolint:lll
	didCfg = `
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": [
        "VerifiableCredential",
        "DomainLinkageCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    }
  ]
}`
	msDoc = `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "Ed25519VerificationKey2018": "https://w3id.org/security#Ed25519VerificationKey2018",
      "publicKeyJwk": {
        "@id": "https://w3id.org/security#publicKeyJwk",
        "@type": "@json"
      }
    }
  ],
  "service": [
    {
      "id": "#linkeddomains",
      "type": "LinkedDomains",
      "serviceEndpoint": {
        "origins": [
          "https://identity.foundation/"
        ]
      }
    },
    {
      "id": "#hub",
      "type": "IdentityHub",
      "serviceEndpoint": {
        "instances": [
          "https://beta.hub.msidentity.com/v1.0/a492cff2-d733-4057-95a5-a71fc3695bc8"
        ],
        "origins": []
      }
    }
  ],
  "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
  "verificationMethod": [
    {
      "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "hbtAIehGcx_wXTFzIYJzrHOwl8IGV8EzRgx__FUEnso"
      }
    }
  ],
  "authentication": [
    "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
  ],
  "assertionMethod": [
    "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
  ]
}`
)

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func TestService_ValidateLinkedDomain(t *testing.T) {
	ctx := context.Background()
	loader := testutil.DocumentLoader(t, ldcontext.Document{
		URL:     contextV1,
		Content: json.RawMessage(didCfgCtxV1),
	})

	client := &mockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(didCfg))),
			}, nil
		},
	}

	doc, err := did.ParseDocument([]byte(msDoc))
	require.NoError(t, err)

	type fields struct {
		getVDR func() vdrapi.Registry
	}
	type args struct {
		signingDID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{
						ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
							if didID != testDID {
								return nil, errors.New("some error")
							}

							return &did.DocResolution{DIDDocument: doc}, nil
						},
					}
				},
			},
			args: args{
				signingDID: testDID,
			},
			wantErr: false,
		},
		{
			name: "VDR resolve error",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{
						ResolveFunc: func(_ string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
							return nil, errors.New("some error")
						},
					}
				},
			},
			args: args{
				signingDID: testDID,
			},
			wantErr: true,
		},
		{
			name: "No LinkedDomains",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{
						ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
							if didID != testDID {
								return nil, errors.New("some error")
							}

							emptyServicesDoc, err := did.ParseDocument([]byte(msDoc))
							require.NoError(t, err)

							emptyServicesDoc.Service = []did.Service{}

							return &did.DocResolution{DIDDocument: emptyServicesDoc}, nil
						},
					}
				},
			},
			args: args{
				signingDID: testDID,
			},
			wantErr: true,
		},
		{
			name: "Unsupported service endpoint structure",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{
						ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
							if didID != testDID {
								return nil, errors.New("some error")
							}

							emptyServicesDoc, err := did.ParseDocument([]byte(msDoc))
							require.NoError(t, err)

							emptyServicesDoc.Service = []did.Service{
								{
									Type:            []interface{}{"IdentityHub"},
									ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://example.com"),
								},
								{
									Type:            []string{"LinkedDomains"},
									ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://example.com"),
								},
							}

							return &did.DocResolution{DIDDocument: emptyServicesDoc}, nil
						},
					}
				},
			},
			args: args{
				signingDID: testDID,
			},
			wantErr: true,
		},
		{
			name: "Invalid domain",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{
						ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
							if didID != testDID {
								return nil, errors.New("some error")
							}

							emptyServicesDoc, err := did.ParseDocument([]byte(msDoc))
							require.NoError(t, err)

							emptyServicesDoc.Service = []did.Service{
								{
									Type: []string{"LinkedDomains"},
									ServiceEndpoint: endpoint.NewDIDCoreEndpoint(
										map[string][]string{
											"origins": {"https://example.com"},
										}),
								},
							}

							return &did.DocResolution{DIDDocument: emptyServicesDoc}, nil
						},
					}
				},
			},
			args: args{
				signingDID: testDID,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				documentLoader: loader,
				vdr:            tt.fields.getVDR(),
				httpClient:     client,
			}
			if err := s.ValidateLinkedDomain(ctx, tt.args.signingDID); (err != nil) != tt.wantErr {
				t.Errorf("ValidateLinkedDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
