/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func GetOrgIDFromOIDC(ctx echo.Context) (string, error) {
	// TODO: resolve orgID from auth token
	authHeader := ctx.Request().Header.Get("Authorization")
	if authHeader == "" || !strings.Contains(authHeader, "Bearer") {
		return "", resterr.NewUnauthorizedError(fmt.Errorf("missing authorization"))
	}

	orgID := authHeader[len("Bearer "):] // for now assume that token is just plain orgID

	return orgID, nil
}
