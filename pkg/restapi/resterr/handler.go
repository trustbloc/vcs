/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"
)

var logger = log.New("rest-err")

func HTTPErrorHandler(err error, c echo.Context) {
	var fositeError *FositeError
	if errors.As(err, &fositeError) {
		err = fositeError.Write()
		if err == nil {
			return
		}
	}

	code, message := processError(err)
	logger.Error("HTTP Error Handler", log.WithHostURL(c.Request().RequestURI), log.WithHTTPStatus(code),
		log.WithAdditionalMessage(fmt.Sprintf("%s", message)))
	sendResponse(c, code, message)
}

func sendResponse(c echo.Context, code int, message interface{}) {
	var err error
	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			logger.Error("head error msg", log.WithError(fmt.Errorf("%v", message)))
			err = c.NoContent(code)
		} else {
			err = c.JSON(code, message)
		}
		if err != nil {
			logger.Error("write http response", log.WithError(err))
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
