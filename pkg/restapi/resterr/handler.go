/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/labstack/echo/v4"
)

var logger = log.New("rest-err")

func HTTPErrorHandler(err error, c echo.Context) {
	code, message := processError(err)
	logger.Errorf("%s -> [%d] %s", c.Request().RequestURI, code, message)
	sendResponse(c, code, message)
}

func sendResponse(c echo.Context, code int, message interface{}) {
	var err error
	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			logger.Errorf("head error msg: %v", message)
			err = c.NoContent(code)
		} else {
			err = c.JSON(code, message)
		}
		if err != nil {
			logger.Errorf("write http response: %s", err.Error())
		}
	}
}

func processError(err error) (int, interface{}) {
	switch v := err.(type) { //nolint: errorlint
	case *echo.HTTPError:
		code, message := v.Code, v.Message
		if v.Internal != nil {
			message = err.Error()
		}

		if strMsg, ok := message.(string); ok {
			message = map[string]interface{}{
				"message": strMsg,
			}
		}

		return code, message

	case *CustomError:
		return v.HTTPCodeMsg()
	default:
		return http.StatusInternalServerError, map[string]interface{}{
			"code":    "generic-error",
			"message": err.Error(),
		}
	}
}
