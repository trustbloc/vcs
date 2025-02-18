/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination fosite_mocks_test.go -self_package mocks -package resterr -source=fosite.go -mock_names fositeErrorWriter=MockFositeErrorWriter

package resterr

import (
	"context"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
)

const (
	FositeAuthorizeError     FositeErrorCode = iota // Authorize request error
	FositeAccessError                               // Token request error
	FositeIntrospectionError                        // Token Introspection error
	FositePARError                                  // PAR error
)

type FositeErrorCode int

type fositeErrorWriter interface {
	WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester fosite.AuthorizeRequester, err error)
	WriteAccessError(ctx context.Context, rw http.ResponseWriter, requester fosite.AccessRequester, err error)
	WriteIntrospectionError(ctx context.Context, rw http.ResponseWriter, err error)
	WritePushedAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar fosite.AuthorizeRequester, err error)
}

type FositeError struct {
	err                error
	code               FositeErrorCode
	ctx                echo.Context
	writer             fositeErrorWriter
	authorizeRequester fosite.AuthorizeRequester
	accessRequester    fosite.AccessRequester
}

func NewFositeError(code FositeErrorCode, ctx echo.Context, w fositeErrorWriter, err error) *FositeError {
	return &FositeError{
		err:    err,
		code:   code,
		ctx:    ctx,
		writer: w,
	}
}

func NewFositeAuthUnauthorizedClientErr(ctx echo.Context, w fositeErrorWriter) *FositeError {
	return NewFositeError(FositeAuthorizeError, ctx, w, fosite.ErrUnauthorizedClient)
}

func NewFositePARUnauthorizedClientErr(ctx echo.Context, w fositeErrorWriter) *FositeError {
	return NewFositeError(FositePARError, ctx, w, fosite.ErrUnauthorizedClient)
}

func NewFositeAuthInvalidRequestErr(ctx echo.Context, w fositeErrorWriter) *FositeError {
	return NewFositeError(FositeAuthorizeError, ctx, w, fosite.ErrInvalidRequest)
}

func NewFositePARInvalidRequestErr(ctx echo.Context, w fositeErrorWriter) *FositeError {
	return NewFositeError(FositePARError, ctx, w, fosite.ErrInvalidRequest)
}

func NewFositeAccessTokenInvalidTokenErr(ctx echo.Context, w fositeErrorWriter) *FositeError {
	return NewFositeError(FositeAccessError, ctx, w, fosite.ErrInvalidTokenFormat)
}

func NewFositeIntrospectTokenInvalidTokenErr(ctx echo.Context, w fositeErrorWriter) *FositeError {
	return NewFositeError(FositeIntrospectionError, ctx, w, fosite.ErrInvalidTokenFormat)
}

func (e *FositeError) WithAuthorizeRequester(requester fosite.AuthorizeRequester) *FositeError {
	e.authorizeRequester = requester
	return e
}

func (e *FositeError) WithAccessRequester(requester fosite.AccessRequester) *FositeError {
	e.accessRequester = requester
	return e
}

func (e *FositeError) Error() string {
	return e.err.Error()
}

func (e *FositeError) Unwrap() error {
	return e.err
}

func (e *FositeError) Write() error {
	switch e.code {
	case FositeAuthorizeError:
		e.writer.WriteAuthorizeError(e.ctx.Request().Context(), e.ctx.Response().Writer, e.authorizeRequester, e.err)
		return nil
	case FositeAccessError:
		e.writer.WriteAccessError(e.ctx.Request().Context(), e.ctx.Response().Writer, e.accessRequester, e.err)
		return nil
	case FositeIntrospectionError:
		e.writer.WriteIntrospectionError(e.ctx.Request().Context(), e.ctx.Response().Writer, e.err)
		return nil
	case FositePARError:
		e.writer.WritePushedAuthorizeError(e.ctx.Request().Context(), e.ctx.Response().Writer, e.authorizeRequester, e.err)
		return nil
	default:
		return fmt.Errorf("usupported fosite error code %d, err %w", e.code, e.err)
	}
}
