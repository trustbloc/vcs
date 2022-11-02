/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package revocation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	vdr2 "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/stretchr/testify/require"
)

const (
	objectID                 = "33c34640-8e48-43ba-9566-32760ab2cdad"
	didID                    = "did:ion:EiCMdVLtzqqW5n6zUC3_srZxWPCseVxKXu9FqQ8LyS1mTA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiI2NmRkNTFmZTBjYWM0ZjFhYWU4MTJkMGFhMTA5YmMyYXZjU2lnbmluZ0tleS0yZTk3NSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJqNVQ4S1FfQ19IRGxSbXlFX1pwRjltbE1RZ3B4N19fMFJQRHhPVmM4dWt3IiwieSI6InpybDBWSllHWnhVLXFjZWt2SlY4NGs5U2x2STQxam53NG4yTS1WMnB4MGMifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJhc3NlcnRpb25NZXRob2QiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoibGlua2VkZG9tYWlucyIsInNlcnZpY2VFbmRwb2ludCI6eyJvcmlnaW5zIjpbImh0dHBzOi8vZGlkLnJvaGl0Z3VsYXRpLmNvbS8iXX0sInR5cGUiOiJMaW5rZWREb21haW5zIn0seyJpZCI6Imh1YiIsInNlcnZpY2VFbmRwb2ludCI6eyJpbnN0YW5jZXMiOlsiaHR0cHM6Ly9iZXRhLmh1Yi5tc2lkZW50aXR5LmNvbS92MS4wL2E0OTJjZmYyLWQ3MzMtNDA1Ny05NWE1LWE3MWZjMzY5NWJjOCJdfSwidHlwZSI6IklkZW50aXR5SHViIn1dfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlDcXRpZnUwSHg4RUVkbGlrVnZIWGpYZzRLb0pZZUV0cDdZeGlvRzVYWmRKZyJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQ1NVQklmYTBXZHBXNm5oVTdNaHlSczRucTFDeEg1V1ZyUjVkUFZYV09MYmciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUF1cGoxRWZsOHdjWlRQZTI3X0lGWEJ3MjlzOEN5SXBRX3UzVkRwUmswdkNRIn19" //nolint:lll
	malformedQueriesURLParam = "W3sic2NoZW1hIjoiaHR0cHM6Ly93M2lkLm9yZy92Yy1zdGF0dXMtbGlzdC0yMDIxL3YxIiwib2JqZWN0SWQiOiIzM2MzNDY0MC04ZTQ4LTQzYmEtOTU2Ni0zMjc2MGFiMmNkYWQifV0="                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        //nolint:lll
	queriesURLParam          = "W3sibWV0aG9kIjoiQ29sbGVjdGlvbnNRdWVyeSIsInNjaGVtYSI6Imh0dHBzOi8vdzNpZC5vcmcvdmMtc3RhdHVzLWxpc3QtMjAyMS92MSIsIm9iamVjdElkIjoiMzNjMzQ2NDAtOGU0OC00M2JhLTk1NjYtMzI3NjBhYjJjZGFkIn1d"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    //nolint:lll
	query                    = "service=IdentityHub&queries=" + queriesURLParam
	didRelativeURL           = didID + "?" + query
	serviceEndpointURL       = "https://identityhub.example.com/"
)

var (
	//go:embed testdata/sample_vc.jwt
	sampleVCJWT string
	//go:embed testdata/identity_hub_response_jwt.json
	identityHubResponseJWT string
)

func getIdentityHubResponse(t *testing.T) IdentityHubResponse {
	t.Helper()

	response := IdentityHubResponse{}
	err := json.Unmarshal([]byte(identityHubResponseJWT), &response)
	require.NoError(t, err)

	return response
}

func TestIdentityHubResponse_GetVCBytes(t *testing.T) {
	rsp := getIdentityHubResponse(t)

	vcBytes, err := rsp.GetVCBytes("unknown")
	require.Nil(t, vcBytes)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to get VC from IdentityHubResponse")

	vcBytes, err = rsp.GetVCBytes(objectID)
	require.NoError(t, err)
	require.Equal(t, sampleVCJWT, string(vcBytes))

	rsp.Replies[0].Entries[0].Data = "malformed"

	vcBytes, err = rsp.GetVCBytes(objectID)
	require.Nil(t, vcBytes)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to decode vc bytes")
}

func TestIdentityHubResponse_checkResponseStatus(t *testing.T) {
	rsp := getIdentityHubResponse(t)

	err := rsp.checkResponseStatus()
	require.NoError(t, err)

	rsp.Replies[0].Status.Code = http.StatusInternalServerError
	rsp.Replies[0].Status.Message = "some error explanation"
	err = rsp.checkResponseStatus()
	require.Error(t, err)
	require.ErrorContains(t, err,
		"unexpected message level status code, got 500, message: some error explanation")

	rsp.Status.Code = http.StatusInternalServerError
	rsp.Status.Message = "some error explanation"
	err = rsp.checkResponseStatus()
	require.Error(t, err)
	require.ErrorContains(t, err,
		"unexpected request level status code, got 500, message: some error explanation")
}

func TestMessage_GetObjectID(t *testing.T) {
	msg := Message{
		Descriptor: map[string]interface{}{
			objectIDKey: objectID,
		},
	}

	val, ok := msg.GetObjectID()
	require.True(t, ok)
	require.Equal(t, objectID, val)

	delete(msg.Descriptor, objectIDKey)
	val, ok = msg.GetObjectID()
	require.False(t, ok)
	require.Empty(t, val)

	msg.Descriptor[objectIDKey] = 123
	val, ok = msg.GetObjectID()
	require.False(t, ok)
	require.Empty(t, val)
}

func TestMessage_IsMethod(t *testing.T) {
	msg := Message{
		Descriptor: map[string]interface{}{
			methodKey: methodCollectionsQuery,
		},
	}

	ok := msg.IsMethod(methodCollectionsQuery)
	require.True(t, ok)

	delete(msg.Descriptor, methodKey)
	ok = msg.IsMethod(methodCollectionsQuery)
	require.False(t, ok)

	msg.Descriptor[methodKey] = 123
	ok = msg.IsMethod(methodCollectionsQuery)
	require.False(t, ok)
}

func TestService_getIdentityHubRequestMeta(t *testing.T) {
	service := &Service{}
	queryValues := url.Values{}

	queryValues.Set("queries", "malformed")
	requestMeta, err := service.getIdentityHubRequestMeta(didID, queryValues)
	require.Nil(t, requestMeta)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to decode \"queries\" key")

	queryValues.Set("queries", "")
	requestMeta, err = service.getIdentityHubRequestMeta(didID, queryValues)
	require.Nil(t, requestMeta)
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to unmarshal queries onto map")

	queryValues.Set("queries", malformedQueriesURLParam)
	requestMeta, err = service.getIdentityHubRequestMeta(didID, queryValues)
	require.Nil(t, requestMeta)
	require.Error(t, err)
	require.ErrorContains(t, err, "objectId is not defined")

	queryValues.Set("queries", queriesURLParam)
	requestMeta, err = service.getIdentityHubRequestMeta(didID, queryValues)
	require.NotNil(t, requestMeta)
	require.NoError(t, err)

	require.Equal(t, requestMeta.objectID, objectID)
	identityHubRequest := IdentityHubRequest{}
	err = json.Unmarshal(requestMeta.payload, &identityHubRequest)
	require.NoError(t, err)

	require.Equal(t, identityHubRequest.Target, didID)
	require.True(t, identityHubRequest.Messages[0].IsMethod(methodCollectionsQuery))
	require.Empty(t, identityHubRequest.Messages[0].Data)
	objID, ok := identityHubRequest.Messages[0].GetObjectID()
	require.True(t, ok)
	require.Equal(t, objID, objectID)
}

func TestService_getQueryValues(t *testing.T) {
	s := Service{}

	queryValues, err := s.getQueryValues("did:example:123")
	require.NoError(t, err)
	require.Len(t, queryValues, 0)

	queryValues, err = s.getQueryValues("did:example:123?a=b;c=d")
	require.Error(t, err)
	require.ErrorContains(t, err, "unable to parse query from didURL")
	require.Len(t, queryValues, 0)

	queryValues, err = s.getQueryValues("did:example:123?a=b&c=d")
	require.NoError(t, err)
	require.Len(t, queryValues, 2)
	require.Equal(t, "b", queryValues.Get("a"))
	require.Equal(t, "d", queryValues.Get("c"))
}

func TestService_getIdentityHubServiceEndpoint(t *testing.T) {
	didDoc := createDIDDoc("did:example:123")
	s := &Service{}

	serviceEndpoint, err := s.getIdentityHubServiceEndpoint(didDoc)
	require.NoError(t, err)
	require.Equal(t, serviceEndpointURL, serviceEndpoint)

	didDoc.Service[0].Type = "did-communication"
	serviceEndpoint, err = s.getIdentityHubServiceEndpoint(didDoc)
	require.Error(t, err)
	require.ErrorContains(t, err, "no identity hub service supplied")
	require.Empty(t, serviceEndpoint)
}

func TestService_resolveDID(t *testing.T) {
	universalResolverVDRI, err := httpbinding.New("https://uniresolver.io/1.0/identifiers",
		httpbinding.WithAccept(func(method string) bool { return method == "ion" }))
	require.NoError(t, err)

	vdrResolver := vdr2.New(vdr2.WithVDR(universalResolverVDRI))
	s := &Service{
		vdr: vdrResolver,
	}
	didDoc, err := s.resolveDID(didRelativeURL)
	require.NoError(t, err)
	require.Equal(t, didDoc.ID, createDIDDoc(didID).ID)

	s = &Service{
		vdr: &vdrmock.MockVDRegistry{
			ResolveErr: errors.New("some error"),
		},
	}
	didDoc, err = s.resolveDID(didRelativeURL)
	require.Error(t, err)
	require.Nil(t, didDoc)
}

func TestService_resolveDIDRelativeUrl(t *testing.T) {
	type fields struct {
		getVDR        func() vdr.Registry
		getHTTPClient func() httpClient
	}
	type args struct {
		didRelativeURL string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				getVDR: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{
						ResolveValue: createDIDDoc("did:trustbloc:abc"),
					}
				},
				getHTTPClient: func() httpClient {
					return &mockHTTPClient{
						doValue: &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewReader([]byte(identityHubResponseJWT))),
						},
						doErr: nil,
					}
				},
			},
			args: args{
				didRelativeURL: didRelativeURL,
			},
			want:    sampleVCJWT,
			wantErr: false,
		},
		{
			name: "resolveDID error",
			fields: fields{
				getVDR: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{
						ResolveErr: errors.New("some error"),
					}
				},
				getHTTPClient: func() httpClient {
					return nil
				},
			},
			args: args{
				didRelativeURL: "did:example:123",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "getQueryValues error",
			fields: fields{
				getVDR: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{
						ResolveValue: createDIDDoc("did:trustbloc:abc"),
					}
				},
				getHTTPClient: func() httpClient {
					return nil
				},
			},
			args: args{
				didRelativeURL: "did:example:123?a=b;c=d",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "getIdentityHubServiceEndpoint error",
			fields: fields{
				getVDR: func() vdr.Registry {
					didDoc := createDIDDoc("did:trustbloc:abc")
					didDoc.Service[0].Type = "LinkedDomains"
					return &vdrmock.MockVDRegistry{
						ResolveValue: didDoc,
					}
				},
				getHTTPClient: func() httpClient {
					return nil
				},
			},
			args: args{
				didRelativeURL: didRelativeURL,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "NewRequestWithContext error",
			fields: fields{
				getVDR: func() vdr.Registry {
					didDoc := createDIDDoc("did:trustbloc:abc")
					didDoc.Service[0].ServiceEndpoint = model.NewDIDCommV1Endpoint(" http://example.com")
					return &vdrmock.MockVDRegistry{
						ResolveValue: didDoc,
					}
				},
				getHTTPClient: func() httpClient {
					return nil
				},
			},
			args: args{
				didRelativeURL: didRelativeURL,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "sendHTTPRequest error",
			fields: fields{
				getVDR: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{
						ResolveValue: createDIDDoc("did:trustbloc:abc"),
					}
				},
				getHTTPClient: func() httpClient {
					return &mockHTTPClient{
						doErr: errors.New("some error"),
					}
				},
			},
			args: args{
				didRelativeURL: didRelativeURL,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "identityHubResponse Unmarshal error",
			fields: fields{
				getVDR: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{
						ResolveValue: createDIDDoc("did:trustbloc:abc"),
					}
				},
				getHTTPClient: func() httpClient {
					return &mockHTTPClient{
						doValue: &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewReader([]byte(""))),
						},
						doErr: nil,
					}
				},
			},
			args: args{
				didRelativeURL: didRelativeURL,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "checkResponseStatus error",
			fields: fields{
				getVDR: func() vdr.Registry {
					return &vdrmock.MockVDRegistry{
						ResolveValue: createDIDDoc("did:trustbloc:abc"),
					}
				},
				getHTTPClient: func() httpClient {
					return &mockHTTPClient{
						doValue: &http.Response{
							StatusCode: http.StatusOK,
							Body: io.NopCloser(bytes.NewReader(
								[]byte(`{"status": { "code": 500 }}`))),
						},
						doErr: nil,
					}
				},
			},
			args: args{
				didRelativeURL: didRelativeURL,
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{
				vdr:        tt.fields.getVDR(),
				httpClient: tt.fields.getHTTPClient(),
			}
			got, err := s.resolveDIDRelativeURL(tt.args.didRelativeURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveDIDRelativeURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(tt.want, string(got)) {
				t.Errorf("resolveDIDRelativeURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func createDIDDoc(didID string) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	creator := didID + "#key1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            serviceTypeIdentityHub,
		ServiceEndpoint: model.NewDIDCommV1Endpoint(serviceEndpointURL),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
	}
}
