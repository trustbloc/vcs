/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"errors"

	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	tenantIDHeader = "X-Tenant-ID"
)

func GetTenantIDFromRequest(ctx echo.Context) (string, error) {
	tenantID := ctx.Request().Header.Get(tenantIDHeader)
	if tenantID == "" {
		return "", resterr.NewUnauthorizedError(errors.New("missing authorization"))
	}

	return tenantID, nil
}
