/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/vcs/internal/logfields"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	oidc4cierr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4ci"
	oidc4vperr "github.com/trustbloc/vcs/pkg/restapi/resterr/oidc4vp"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc6749"
	"github.com/trustbloc/vcs/pkg/restapi/resterr/rfc7591"
)

var logger = log.New("rest-err")

func HTTPErrorHandler(tracer trace.Tracer) func(err error, c echo.Context) {
	return func(err error, c echo.Context) {
		ctx, span := tracer.Start(c.Request().Context(), "HTTPErrorHandler")
		defer span.End()

		var fositeError *resterr.FositeError
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
	var echoHTTPError *echo.HTTPError
	if errors.As(err, &echoHTTPError) {
		code, message := echoHTTPError.Code, echoHTTPError.Message
		if echoHTTPError.Internal != nil {
			message = err.Error()
		}

		if strMsg, ok := message.(string); ok {
			message = map[string]interface{}{
				"message": strMsg,
			}
		}

		return code, message
	}

	var oidc4ciError *oidc4cierr.Error
	if errors.As(err, &oidc4ciError) {
		return oidc4ciError.HTTPStatus, oidc4ciError
	}

	var oidc4vpError *oidc4vperr.Error
	if errors.As(err, &oidc4vpError) {
		return oidc4vpError.HTTPStatus, oidc4vpError
	}

	var rfc6749Error *rfc6749.Error
	if errors.As(err, &rfc6749Error) {
		return rfc6749Error.HTTPStatus, rfc6749Error
	}

	var rfc7591Error *rfc7591.Error
	if errors.As(err, &rfc7591Error) {
		return rfc7591Error.HTTPStatus, rfc7591Error
	}

	return http.StatusInternalServerError, map[string]interface{}{
		"error":             "generic-error",
		"error_description": err.Error(),
	}
}
