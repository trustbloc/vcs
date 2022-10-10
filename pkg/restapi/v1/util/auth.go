/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"github.com/pkg/errors"

	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	userHeader = "X-User"
)

func GetOrgIDFromOIDC(ctx echo.Context) (string, error) {
	orgID := ctx.Request().Header.Get(userHeader)
	if orgID == "" {
		return "", resterr.NewUnauthorizedError(errors.New("missing authorization"))
	}

	return orgID, nil
}
