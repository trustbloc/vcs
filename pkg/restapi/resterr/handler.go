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
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/internal/logfields"
)

var logger = log.New("rest-err")

func HTTPErrorHandler(tracer trace.Tracer) func(err error, c echo.Context) {
	return func(err error, c echo.Context) {
		ctx, span := tracer.Start(c.Request().Context(), "HTTPErrorHandler")
		defer span.End()

		var fositeError *FositeError
		if errors.As(err, &fositeError) {
			span.SetStatus(codes.Error, "fosite error")
			span.RecordError(err)

			err = fositeError.Write()
			if err == nil {
				return
			}
		}

		code, message := processError(err)

		span.SetStatus(codes.Error, fmt.Sprintf("%s", message))
		span.RecordError(err)

		logger.Errorc(ctx, "HTTP Error Handler",
			log.WithURL(c.Request().RequestURI),
			log.WithHTTPStatus(code),
			logfields.WithAdditionalMessage(fmt.Sprintf("%s", message)),
		)

		sendResponse(c, code, message)
	}
}

func sendResponse(c echo.Context, code int, message interface{}) {
	var err error
	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			logger.Errorc(c.Request().Context(), "head error msg", log.WithError(fmt.Errorf("%v", message)))
			err = c.NoContent(code)
		} else {
			err = c.JSON(code, message)
		}
		if err != nil {
			logger.Errorc(c.Request().Context(), "write http response", log.WithError(err))
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
