/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mw

import (
	"crypto/subtle"
	"net/http"

	"github.com/labstack/echo/v4"
)

const (
	header = "X-API-Key"
)

// APIKeyAuth returns a middleware that authenticates requests using the API key from X-API-Key header.
func APIKeyAuth(apiKey string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
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
