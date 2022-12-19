package handlers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/stretchr/testify/assert"

	"github.com/trustbloc/vcs/pkg/restapi/handlers"
)

const (
	targetGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

func TestCanHandleTokenEndpointRequest(t *testing.T) {
	c := &handlers.PreAuthorizeGrantHandler{}

	assert.True(t, c.CanHandleTokenEndpointRequest(context.TODO(), &fosite.AccessRequest{
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
	}))
	assert.False(t, c.CanHandleTokenEndpointRequest(context.TODO(), &fosite.AccessRequest{
		GrantTypes: []string{"code"},
	}))
}

func TestCanSkipAuth(t *testing.T) {
	c := &handlers.PreAuthorizeGrantHandler{}
	assert.True(t, c.CanSkipClientAuth(context.TODO(), nil))
}

func TestHandleTokenEndpoint(t *testing.T) {
	c := &handlers.PreAuthorizeGrantHandler{}
	assert.NoError(t, c.HandleTokenEndpointRequest(context.TODO(), nil))
}

type strategyProxy struct {
	oauth2.AccessTokenStrategy
	oauth2.RefreshTokenStrategy
	oauth2.AuthorizeCodeStrategy
}

func TestPopulateTokenEndpoint(t *testing.T) {
	responderMock := NewMockAccessResponder(gomock.NewController(t))
	accessTokenStrategy := NewMockAccessTokenStrategy(gomock.NewController(t))
	refreshTokenStrategy := NewMockRefreshTokenStrategy(gomock.NewController(t))
	storageMock := NewMockCoreStorage(gomock.NewController(t))

	strategy := &strategyProxy{
		AccessTokenStrategy:  accessTokenStrategy,
		RefreshTokenStrategy: refreshTokenStrategy,
	}

	factory := handlers.OAuth2PreAuthorizeFactory(
		&fosite.Config{},
		storageMock,
		strategy,
	).(*handlers.PreAuthorizeGrantHandler)
	assert.NotNil(t, factory)

	originalRequest := &fosite.AccessRequest{
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		Request: fosite.Request{
			RequestedScope:    []string{"scope1", "scope2"},
			RequestedAudience: []string{"a1", "a2"},
			Session:           &fosite.DefaultSession{},
		},
	}
	assert.Empty(t, originalRequest.GrantedScope)
	assert.Empty(t, originalRequest.GrantedAudience)

	responderMock.EXPECT().SetScopes(fosite.Arguments{"scope1", "scope2"})

	accessToken := uuid.NewString()
	accessSign := uuid.NewString()
	refreshToken := uuid.NewString()
	refreshSign := uuid.NewString()

	accessTokenStrategy.EXPECT().GenerateAccessToken(gomock.Any(), originalRequest).
		Return(accessToken, accessSign, nil)
	refreshTokenStrategy.EXPECT().GenerateRefreshToken(gomock.Any(), originalRequest).
		Return(refreshToken, refreshSign, nil)

	storageMock.EXPECT().CreateAccessTokenSession(gomock.Any(), accessSign, originalRequest).Return(nil)
	storageMock.EXPECT().CreateRefreshTokenSession(gomock.Any(), refreshSign, gomock.Any()).Return(nil)

	responderMock.EXPECT().SetAccessToken(accessToken)
	responderMock.EXPECT().SetTokenType("bearer")
	responderMock.EXPECT().SetExpiresIn(gomock.Any())
	responderMock.EXPECT().SetExtra("refresh_token", refreshToken)

	factory.PopulateTokenEndpointResponse(context.TODO(), originalRequest, responderMock)
}

func TestPopulateTokenWithWrongType(t *testing.T) {
	factory := &handlers.PreAuthorizeGrantHandler{}
	assert.NoError(t, factory.PopulateTokenEndpointResponse(context.TODO(), &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{"code"},
	}, nil))
}

func TestPopulateWithAccessTokenErr(t *testing.T) {
	accessStrategy := NewMockAccessTokenStrategy(gomock.NewController(t))
	accessStrategy.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any()).
		Return("", "", errors.New("can not generate1"))

	factory := &handlers.PreAuthorizeGrantHandler{
		AccessTokenStrategy: accessStrategy,
	}
	assert.ErrorContains(t, factory.PopulateTokenEndpointResponse(context.TODO(), &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{targetGrantType},
	}, &fosite.AccessResponse{}), "can not generate1")
}

func TestPopulateWithRefreshTokenErr(t *testing.T) {
	accessStrategy := NewMockAccessTokenStrategy(gomock.NewController(t))
	accessStrategy.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any()).
		Return("a", "b", nil)

	refreshTokenStrategy := NewMockRefreshTokenStrategy(gomock.NewController(t))
	refreshTokenStrategy.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any()).
		Return("", "", errors.New("can not generate2"))

	factory := &handlers.PreAuthorizeGrantHandler{
		AccessTokenStrategy:  accessStrategy,
		RefreshTokenStrategy: refreshTokenStrategy,
	}
	assert.ErrorContains(t, factory.PopulateTokenEndpointResponse(context.TODO(), &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{targetGrantType},
	}, &fosite.AccessResponse{}), "server_error")
}

func TestCanNotCreteAccessTokenSession(t *testing.T) {
	accessStrategy := NewMockAccessTokenStrategy(gomock.NewController(t))
	accessStrategy.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any()).
		Return("a", "b", nil)

	refreshTokenStrategy := NewMockRefreshTokenStrategy(gomock.NewController(t))
	refreshTokenStrategy.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any()).
		Return("", "", nil)

	storageMock := NewMockCoreStorage(gomock.NewController(t))
	storageMock.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(errors.New("store err"))

	factory := &handlers.PreAuthorizeGrantHandler{
		AccessTokenStrategy:  accessStrategy,
		RefreshTokenStrategy: refreshTokenStrategy,
		CoreStorage:          storageMock,
	}
	assert.ErrorContains(t, factory.PopulateTokenEndpointResponse(context.TODO(), &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{targetGrantType},
	}, &fosite.AccessResponse{}), "store err")
}

func TestCanNotCreteRefreshTokenSession(t *testing.T) {
	accessStrategy := NewMockAccessTokenStrategy(gomock.NewController(t))
	accessStrategy.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any()).
		Return("a", "b", nil)

	refreshTokenStrategy := NewMockRefreshTokenStrategy(gomock.NewController(t))
	refreshTokenStrategy.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any()).
		Return("d", "c", nil)

	storageMock := NewMockCoreStorage(gomock.NewController(t))
	storageMock.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil)
	storageMock.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(errors.New("store err2"))

	factory := &handlers.PreAuthorizeGrantHandler{
		AccessTokenStrategy:  accessStrategy,
		RefreshTokenStrategy: refreshTokenStrategy,
		CoreStorage:          storageMock,
		Config:               &fosite.Config{},
	}
	assert.ErrorContains(t, factory.PopulateTokenEndpointResponse(context.TODO(), &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{targetGrantType},
		Request: fosite.Request{
			Session: &fosite.DefaultSession{},
		},
	}, &fosite.AccessResponse{}), "server_error")
}

func TestCreateWithoutRefreshToken(t *testing.T) {
	accessStrategy := NewMockAccessTokenStrategy(gomock.NewController(t))
	accessStrategy.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any()).
		Return("a", "b", nil)

	refreshTokenStrategy := NewMockRefreshTokenStrategy(gomock.NewController(t))
	refreshTokenStrategy.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any()).
		Return("", "", nil)

	storageMock := NewMockCoreStorage(gomock.NewController(t))
	storageMock.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil)

	factory := &handlers.PreAuthorizeGrantHandler{
		AccessTokenStrategy:  accessStrategy,
		RefreshTokenStrategy: refreshTokenStrategy,
		CoreStorage:          storageMock,
		Config:               &fosite.Config{},
	}
	response := &fosite.AccessResponse{
		Extra: map[string]interface{}{},
	}

	assert.NoError(t, factory.PopulateTokenEndpointResponse(context.TODO(), &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{targetGrantType},
		Request: fosite.Request{
			Session: &fosite.DefaultSession{
				ExpiresAt: map[fosite.TokenType]time.Time{
					fosite.AccessToken: time.Now().Add(24 * time.Hour),
				},
			},
		},
	}, response))

	assert.Equal(t, "a", response.AccessToken)
	assert.Len(t, response.Extra, 2)
}
