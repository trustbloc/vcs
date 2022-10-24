/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/component/privateapi"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/service/oidc4vc"
)

func TestService_InitiateInteraction(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		mockWellKnownService = NewMockWellKnownService[oidc4vc.ClientWellKnown](gomock.NewController(t))
		issuanceReq          *oidc4vc.InitiateIssuanceRequest
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						CredentialTemplate: &verifiable.Credential{
							ID: "templateID",
						},
					},
				}, nil)
				mockWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), gomock.Any()).Return(
					&oidc4vc.ClientWellKnown{
						InitiateIssuanceEndpoint: "https://wallet.example.com/initiate_issuance",
					}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Credential template ID is required",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateIDRequired)
			},
		},
		{
			name: "Credential template not found",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID3",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.ErrorIs(t, err, oidc4vc.ErrCredentialTemplateNotFound)
			},
		},
		{
			name: "Client initiate issuance URL takes precedence over client well-known parameter",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClientWellKnownURL:        "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "https://wallet.example.com/initiate_issuance")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to do well-known request",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)
				mockWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("invalid json"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Custom initiate issuance URL when fail to decode well-known config",
			setup: func() {
				mockTransactionStore.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)
				mockWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("invalid json"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID: "templateID",
					ClientWellKnownURL:   "https://wallet.example.com/.well-known/openid-configuration",
					ClaimEndpoint:        "https://vcs.pb.example.com/claim",
					OpState:              "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.NoError(t, err)
				require.Contains(t, resp.InitiateIssuanceURL, "openid-initiate-issuance://")
			},
		},
		{
			name: "Fail to store transaction",
			setup: func() {
				mockTransactionStore.EXPECT().Create(
					gomock.Any(),
					gomock.Any(),
					gomock.Any(),
				).Return(nil, fmt.Errorf("store error"))

				issuanceReq = &oidc4vc.InitiateIssuanceRequest{
					CredentialTemplateID:      "templateID",
					ClientInitiateIssuanceURL: "https://wallet.example.com/initiate_issuance",
					ClaimEndpoint:             "https://vcs.pb.example.com/claim",
					OpState:                   "eyJhbGciOiJSU0Et",
				}
			},
			check: func(t *testing.T, resp *oidc4vc.InitiateIssuanceResponse, err error) {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), "store error")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4vc.NewService(&oidc4vc.Config{
				TransactionStore:       mockTransactionStore,
				ClientWellKnownService: mockWellKnownService,
				IssuerVCSPublicHost:    "https://vcs.pb.example.com/oidc",
			})
			require.NoError(t, err)

			resp, err := svc.InitiateInteraction(context.Background(), issuanceReq, &profileapi.Issuer{
				OIDCConfig: &profileapi.OIDC4VCConfig{},
				CredentialTemplates: []*verifiable.Credential{
					{
						ID:    "templateID",
						Types: []string{"VerifiableCredential", "UniversityDegreeCredential"},
					},
					{
						ID:    "templateID2",
						Types: []string{"VerifiableCredential", "PermanentResidentCard"},
					},
				},
			})
			tt.check(t, resp, err)
		})
	}
}

func TestService_HandlePAR(t *testing.T) {
	var (
		mockTransactionStore = NewMockTransactionStore(gomock.NewController(t))
		ad                   *oidc4vc.AuthorizationDetails
	)

	tests := []struct {
		name  string
		setup func()
		check func(t *testing.T, txID oidc4vc.TxID, err error)
	}{
		{
			name: "Success",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				ad = &oidc4vc.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, txID oidc4vc.TxID, err error) {
				require.NoError(t, err)
				require.Equal(t, oidc4vc.TxID("txID"), txID)
			},
		},
		{
			name: "Credential type mismatch",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				ad = &oidc4vc.AuthorizationDetails{
					CredentialType: "NotSupportedCredentialType",
					Format:         vcsverifiable.Ldp,
				}
			},
			check: func(t *testing.T, txID oidc4vc.TxID, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "credential type mismatch")
			},
		},
		{
			name: "Credential format mismatch",
			setup: func() {
				mockTransactionStore.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{
					ID: "txID",
					TransactionData: oidc4vc.TransactionData{
						AuthorizationDetails: &oidc4vc.AuthorizationDetails{
							CredentialType: "UniversityDegreeCredential",
							Format:         vcsverifiable.Ldp,
						},
					},
				}, nil)

				ad = &oidc4vc.AuthorizationDetails{
					CredentialType: "UniversityDegreeCredential",
					Format:         vcsverifiable.Jwt,
				}
			},
			check: func(t *testing.T, txID oidc4vc.TxID, err error) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "format mismatch")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			svc, err := oidc4vc.NewService(&oidc4vc.Config{
				TransactionStore: mockTransactionStore,
			})
			require.NoError(t, err)

			resp, err := svc.HandlePAR(context.Background(), "opState", ad)
			tt.check(t, resp, err)
		})
	}
}

func TestHandleAuthorize(t *testing.T) {
	privateAPI := NewMockPrivateAPIClient(gomock.NewController(t))
	expectedRedirectURL := "https://trust.com/?qqq=123"

	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		PrivateAPIClient: privateAPI,
	})
	assert.NoError(t, err)

	opState := uuid.NewString()
	uri, err := url.Parse("https://google.com/test?qq=1234")
	assert.NoError(t, err)

	req := oidc4vc.InternalAuthorizationResponder{
		RedirectURI: uri,
		RespondMode: "some_respond_mode",
		AuthorizeResponse: fosite.AuthorizeResponse{
			Header: http.Header{
				"sadasd": []string{"val1", "val2"},
			},
			Parameters: url.Values{},
		},
	}

	privateAPI.EXPECT().PrepareClaimDataAuthZ(gomock.Any(), gomock.Any()).DoAndReturn(func(
		ctx context.Context,
		request *privateapi.PrepareClaimDataAuthZRequest,
	) (*privateapi.PrepareClaimDataAuthZResponse, error) {
		assert.Equal(t, opState, request.OpState)
		assert.Equal(t, req.RedirectURI, request.Responder.RedirectURI)
		assert.Equal(t, req.RespondMode, request.Responder.RespondMode)
		assert.Equal(t, req.AuthorizeResponse, request.Responder.AuthorizeResponse)

		return &privateapi.PrepareClaimDataAuthZResponse{
			RedirectURI: expectedRedirectURL,
		}, nil
	})

	redirectURL, err := svc.HandleAuthorize(context.TODO(), opState, req)
	assert.NoError(t, err)
	assert.Equal(t, expectedRedirectURL, redirectURL)
}

func TestHandleAuthorizeError(t *testing.T) {
	errorStr := "unexpected error"
	privateAPI := NewMockPrivateAPIClient(gomock.NewController(t))

	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		PrivateAPIClient: privateAPI,
	})
	assert.NoError(t, err)

	opState := uuid.NewString()

	privateAPI.EXPECT().PrepareClaimDataAuthZ(gomock.Any(), gomock.Any()).Return(nil, errors.New(errorStr))
	redirectURL, err := svc.HandleAuthorize(context.TODO(), opState, oidc4vc.InternalAuthorizationResponder{})

	assert.Empty(t, redirectURL)
	assert.ErrorContains(t, err, errorStr)
}

func TestPrepareClaimDataAuthZ(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	issuerWellKnownService := NewMockWellKnownService[oidc4vc.IssuerWellKnown](gomock.NewController(t))
	issuerWellKnownURL := "https://truest/.well_known"
	issuerWellTokenEndpoint := "https://truest/token_endpoint"
	issuerWellAuthEndpoint := "https://truest/auth_endpoint"

	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		TransactionStore:       store,
		IssuerWellKnownService: issuerWellKnownService,
	})

	opState := uuid.NewString()
	assert.NoError(t, err)
	parsedURL, err := url.Parse("https://trust/path?qwery=1")
	assert.NoError(t, err)

	req := privateapi.PrepareClaimDataAuthZRequest{
		OpState: opState,
		Responder: privateapi.PrepareClaimResponder{
			RedirectURI: parsedURL,
			RespondMode: "resp",
			AuthorizeResponse: fosite.AuthorizeResponse{
				Header: map[string][]string{
					"header1": {"value1", "value2"},
				},
				Parameters: parsedURL.Query(),
			},
		},
	}

	storeTx := &oidc4vc.Transaction{
		ID: oidc4vc.TxID("213456"),
		TransactionData: oidc4vc.TransactionData{
			OIDC4VCConfig: profileapi.OIDC4VCConfig{
				IssuerWellKnown: issuerWellKnownURL,
				ClientID:        "123",
			},
		},
	}

	store.EXPECT().FindByOpState(gomock.Any(), opState).Return(storeTx, nil)
	issuerWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), issuerWellKnownURL).Return(
		&oidc4vc.IssuerWellKnown{
			TokenEndpoint:         issuerWellTokenEndpoint,
			AuthorizationEndpoint: issuerWellAuthEndpoint,
		}, nil)

	store.EXPECT().Update(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, tx *oidc4vc.Transaction) error {
			assert.Equal(t, storeTx.ID, tx.ID)
			assert.Equal(t, req.Responder.RedirectURI, storeTx.InternalAuthorizationResponder.RedirectURI)
			assert.Equal(t, req.Responder.RespondMode, storeTx.InternalAuthorizationResponder.RespondMode)
			assert.Equal(t, req.Responder.AuthorizeResponse, storeTx.InternalAuthorizationResponder.AuthorizeResponse)

			return nil
		})

	resp, err := svc.PrepareClaimDataAuthZ(context.TODO(), req)
	assert.NoError(t, err)

	assert.Equal(t, fmt.Sprintf("%v?client_id=%v&redirect_uri=callback&"+
		"response_type=code&state=%v", issuerWellAuthEndpoint, storeTx.TransactionData.OIDC4VCConfig.ClientID,
		opState), resp.RedirectURI)
}

func TestPrepareClaimDataAuthZFailState(t *testing.T) {
	errStr := "invalid opState"

	store := NewMockTransactionStore(gomock.NewController(t))
	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(nil, errors.New(errStr))
	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		TransactionStore: store,
	})

	assert.NoError(t, err)
	resp, err := svc.PrepareClaimDataAuthZ(context.TODO(), privateapi.PrepareClaimDataAuthZRequest{})
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, errStr)
}

func TestPrepareClaimDataAuthZFailWellKnown(t *testing.T) {
	errStr := "invalid wellKnown"

	store := NewMockTransactionStore(gomock.NewController(t))
	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)

	issuerWellKnownService := NewMockWellKnownService[oidc4vc.IssuerWellKnown](gomock.NewController(t))
	issuerWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), gomock.Any()).
		Return(nil, errors.New(errStr))

	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		TransactionStore:       store,
		IssuerWellKnownService: issuerWellKnownService,
	})

	assert.NoError(t, err)
	resp, err := svc.PrepareClaimDataAuthZ(context.TODO(), privateapi.PrepareClaimDataAuthZRequest{})
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, errStr)
}

func TestPrepareClaimDataAuthZFailRedirectUri(t *testing.T) {
	store := NewMockTransactionStore(gomock.NewController(t))
	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)

	issuerWellKnownService := NewMockWellKnownService[oidc4vc.IssuerWellKnown](gomock.NewController(t))
	issuerWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), gomock.Any()).
		Return(&oidc4vc.IssuerWellKnown{}, nil)

	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		TransactionStore:       store,
		IssuerVCSPublicHost:    "postgres://user:abc{DEf1=ghi@example.com:5432/db?sslmode=require",
		IssuerWellKnownService: issuerWellKnownService,
	})

	assert.NoError(t, err)
	resp, err := svc.PrepareClaimDataAuthZ(context.TODO(), privateapi.PrepareClaimDataAuthZRequest{})
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "net/url: invalid userinfo")
}

func TestPrepareClaimDataAuthZFailStoreUpdate(t *testing.T) {
	errStr := "invalid store"

	store := NewMockTransactionStore(gomock.NewController(t))
	store.EXPECT().FindByOpState(gomock.Any(), gomock.Any()).Return(&oidc4vc.Transaction{}, nil)

	issuerWellKnownService := NewMockWellKnownService[oidc4vc.IssuerWellKnown](gomock.NewController(t))
	issuerWellKnownService.EXPECT().GetWellKnownConfiguration(gomock.Any(), gomock.Any()).
		Return(&oidc4vc.IssuerWellKnown{}, nil)

	svc, err := oidc4vc.NewService(&oidc4vc.Config{
		TransactionStore:       store,
		IssuerWellKnownService: issuerWellKnownService,
	})

	store.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New(errStr))

	assert.NoError(t, err)
	resp, err := svc.PrepareClaimDataAuthZ(context.TODO(), privateapi.PrepareClaimDataAuthZRequest{})
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, errStr)
}
