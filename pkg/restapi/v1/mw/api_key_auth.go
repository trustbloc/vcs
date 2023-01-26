/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint:cyclop
package mw

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

//nolint:gosec
const (
	header                     = "X-API-Key"
	healthCheckPath            = "/healthcheck"
	statusCheckPath            = "/credentials/status/"
	requestObjectPath          = "/request-object/"
	checkAuthorizationResponse = "/verifier/interactions/authorization-response"
	oidcAuthorize              = "/oidc/authorize"
	oidcRedirect               = "/oidc/redirect"
	oidcPresent                = "/oidc/present"
	oidcToken                  = "/oidc/token"
	oidcCredential             = "/oidc/credential"
	oidcWellKnown              = "/.well-known/openid-configuration"
)

// APIKeyAuth returns a middleware that authenticates requests using the API key from X-API-Key header.
func APIKeyAuth(apiKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			currentPath := strings.ToLower(c.Request().URL.Path)

			// TODO: Implement a better way to support public API.

			if strings.HasSuffix(currentPath, healthCheckPath) {
				return next(c)
			}

			if strings.HasPrefix(currentPath, requestObjectPath) {
				return next(c)
			}

			if strings.Contains(currentPath, statusCheckPath) {
				return next(c)
			}

			if strings.HasPrefix(currentPath, checkAuthorizationResponse) {
				return next(c)
			}

			if strings.HasPrefix(currentPath, oidcAuthorize) ||
				strings.HasPrefix(currentPath, oidcRedirect) ||
				strings.HasPrefix(currentPath, oidcPresent) ||
				strings.HasPrefix(currentPath, oidcToken) ||
				strings.HasPrefix(currentPath, oidcCredential) ||
				strings.HasSuffix(currentPath, oidcWellKnown) {
				return next(c)
			}

			apiKeyHeader := c.Request().Header.Get(header)
			if subtle.ConstantTimeCompare([]byte(apiKeyHeader), []byte(apiKey)) != 1 {
				return &echo.HTTPError{
					Code:    http.StatusUnauthorized,
					Message: "Unauthorized",
				}
			}

			return next(c)
		}
	}
}
