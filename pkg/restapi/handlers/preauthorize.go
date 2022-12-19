package handlers

//go:generate mockgen -package handlers_test -destination preauthorize_mock_test.go github.com/ory/fosite AccessResponder
//go:generate mockgen -package handlers_test -destination preauthorize_mock_handler_test.go github.com/ory/fosite/handler/oauth2 CoreStorage,AccessTokenStrategy,RefreshTokenStrategy

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"
	"github.com/samber/lo"
)

type PreAuthorizeGrantHandler struct {
	AccessTokenStrategy    oauth2.AccessTokenStrategy
	RefreshTokenStrategy   oauth2.RefreshTokenStrategy
	AuthorizeCodeStrategy  oauth2.AuthorizeCodeStrategy
	CoreStorage            oauth2.CoreStorage
	TokenRevocationStorage oauth2.TokenRevocationStorage
	Config                 interface {
		fosite.AuthorizeCodeLifespanProvider
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RedirectSecureCheckerProvider
		fosite.RefreshTokenScopesProvider
		fosite.OmitRedirectScopeParamProvider
		fosite.SanitationAllowedProvider
	}
}

const (
	grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

func (c *PreAuthorizeGrantHandler) CanHandleTokenEndpointRequest(
	_ context.Context,
	requester fosite.AccessRequester,
) bool {
	return requester.GetGrantTypes().ExactOne(grantType)
}

func (c *PreAuthorizeGrantHandler) CanSkipClientAuth(
	_ context.Context,
	_ fosite.AccessRequester,
) bool {
	return true
}

func (c *PreAuthorizeGrantHandler) HandleTokenEndpointRequest(
	_ context.Context,
	_ fosite.AccessRequester,
) error {
	return nil
}

func (c *PreAuthorizeGrantHandler) PopulateTokenEndpointResponse(
	ctx context.Context,
	requester fosite.AccessRequester,
	responder fosite.AccessResponder,
) error {
	if !lo.Contains(requester.GetGrantTypes(), grantType) {
		return nil
	}

	for _, scope := range requester.GetRequestedScopes() {
		requester.GrantScope(scope)
	}
	for _, audience := range requester.GetRequestedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return err
	}

	refresh, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester); err != nil {
		return err
	}

	if refresh != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(
		requester.GetClient(),
		fosite.GrantTypeAuthorizationCode,
		fosite.AccessToken,
		c.Config.GetAccessTokenLifespan(ctx),
	)
	responder.SetExpiresIn(c.getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	return nil
}

func (c *PreAuthorizeGrantHandler) getExpiresIn(
	r fosite.Requester,
	key fosite.TokenType,
	defaultLifespan time.Duration,
	now time.Time,
) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}

// OAuth2PreAuthorizeFactory creates an OAuth2 pre-authorize code grant handler.
func OAuth2PreAuthorizeFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &PreAuthorizeGrantHandler{
		AccessTokenStrategy:  strategy.(oauth2.AccessTokenStrategy),
		RefreshTokenStrategy: strategy.(oauth2.RefreshTokenStrategy),
		CoreStorage:          storage.(oauth2.CoreStorage),
		Config:               config,
	}
}
