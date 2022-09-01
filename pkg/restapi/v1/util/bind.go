/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

const (
	requestBody = "requestBody"
)

func ReadBody(ctx echo.Context, body interface{}) error {
	if err := ctx.Bind(body); err != nil {
		return resterr.NewValidationError(resterr.InvalidValue, requestBody, err)
	}
	return nil
}

func WriteOutput(ctx echo.Context) func(output interface{}, err error) error {
	return func(output interface{}, err error) error {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, output)
	}
}
