/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"errors"

	"github.com/labstack/echo/v4"
)

const (
	tenantIDHeader = "X-Tenant-ID"
)

func GetTenantIDFromRequest(e echo.Context) (string, error) {
	tenantID := e.Request().Header.Get(tenantIDHeader)
	if tenantID == "" {
		return "", errors.New("missing authorization")
	}

	return tenantID, nil
}
