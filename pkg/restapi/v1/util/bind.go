/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
)

func WriteOutput(ctx echo.Context) func(output interface{}, err error) error {
	return WriteOutputWithCode(http.StatusOK, ctx)
}

func WriteOutputWithCode(code int, ctx echo.Context) func(output interface{}, err error) error {
	return func(output interface{}, err error) error {
		if err != nil {
			return err
		}

		b, err := json.Marshal(output)
		if err != nil {
			return err
		}

		return ctx.JSONBlob(code, b)
	}
}

func WriteOutputWithContentType(ctx echo.Context) func(output interface{}, ct string, err error) error {
	return func(output interface{}, ct string, err error) error {
		if err != nil {
			return err
		}

		b, err := json.Marshal(output)
		if err != nil {
			return err
		}

		return ctx.Blob(http.StatusOK, ct, b)
	}
}

func WriteRawOutputWithContentType(ctx echo.Context) func(output []byte, ct string, err error) error {
	return func(output []byte, ct string, err error) error {
		if err != nil {
			return err
		}

		return ctx.Blob(http.StatusOK, ct, output)
	}
}
