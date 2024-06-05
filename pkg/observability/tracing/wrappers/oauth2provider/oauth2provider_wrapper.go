/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination gomocks_test.go -package oauth2provider . Provider

//nolint:lll
package oauth2provider

import (
	"context"
	"net/http"

	"github.com/ory/fosite"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type Provider fosite.OAuth2Provider

type Wrapper struct {
	provider Provider
	tracer   trace.Tracer
}

func Wrap(provider Provider, tracer trace.Tracer) *Wrapper {
	return &Wrapper{provider: provider, tracer: tracer}
}

func (w *Wrapper) NewAuthorizeRequest(ctx context.Context, req *http.Request) (fosite.AuthorizeRequester, error) {
	return w.provider.NewAuthorizeRequest(ctx, req)
}

func (w *Wrapper) NewAuthorizeResponse(ctx context.Context, requester fosite.AuthorizeRequester, session fosite.Session) (fosite.AuthorizeResponder, error) {
	return w.provider.NewAuthorizeResponse(ctx, requester, session)
}

func (w *Wrapper) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester fosite.AuthorizeRequester, err error) {
	w.provider.WriteAuthorizeError(ctx, rw, requester, err)
}

func (w *Wrapper) WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester fosite.AuthorizeRequester, responder fosite.AuthorizeResponder) {
	w.provider.WriteAuthorizeResponse(ctx, rw, requester, responder)
}

func (w *Wrapper) NewAccessRequest(ctx context.Context, req *http.Request, session fosite.Session) (fosite.AccessRequester, error) {
	ctx, span := w.tracer.Start(ctx, "oauth2provider.NewAccessRequest")
	defer span.End()

	ar, err := w.provider.NewAccessRequest(ctx, req, session)
	if err != nil {
		return nil, err
	}

	return ar, nil
}

func (w *Wrapper) NewAccessResponse(ctx context.Context, requester fosite.AccessRequester) (fosite.AccessResponder, error) {
	ctx, span := w.tracer.Start(ctx, "oauth2provider.NewAccessResponse")
	defer span.End()

	ar, err := w.provider.NewAccessResponse(ctx, requester)
	if err != nil {
		return nil, err
	}

	return ar, nil
}

func (w *Wrapper) WriteAccessError(ctx context.Context, rw http.ResponseWriter, requester fosite.AccessRequester, err error) {
	ctx, span := w.tracer.Start(ctx, "oauth2provider.WriteAccessError")
	defer span.End()

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	}

	w.provider.WriteAccessError(ctx, rw, requester, err)
}

func (w *Wrapper) WriteAccessResponse(ctx context.Context, rw http.ResponseWriter, requester fosite.AccessRequester, responder fosite.AccessResponder) {
	ctx, span := w.tracer.Start(ctx, "oauth2provider.WriteAccessResponse")
	defer span.End()

	w.provider.WriteAccessResponse(ctx, rw, requester, responder)
}

func (w *Wrapper) NewRevocationRequest(ctx context.Context, r *http.Request) error {
	return w.provider.NewRevocationRequest(ctx, r)
}

func (w *Wrapper) WriteRevocationResponse(ctx context.Context, rw http.ResponseWriter, err error) {
	w.provider.WriteRevocationResponse(ctx, rw, err)
}

func (w *Wrapper) IntrospectToken(ctx context.Context, token string, tokenUse fosite.TokenUse, session fosite.Session, scope ...string) (fosite.TokenUse, fosite.AccessRequester, error) {
	ctx, span := w.tracer.Start(ctx, "oauth2provider.IntrospectToken")
	defer span.End()

	span.SetAttributes(attribute.String("tokenUse", string(tokenUse)))
	span.SetAttributes(attribute.StringSlice("scope", scope))

	tokenType, ar, err := w.provider.IntrospectToken(ctx, token, tokenUse, session, scope...)
	if err != nil {
		return tokenType, ar, err
	}

	return tokenType, ar, err
}

func (w *Wrapper) NewIntrospectionRequest(ctx context.Context, r *http.Request, session fosite.Session) (fosite.IntrospectionResponder, error) {
	return w.provider.NewIntrospectionRequest(ctx, r, session)
}

func (w *Wrapper) WriteIntrospectionError(ctx context.Context, rw http.ResponseWriter, err error) {
	w.provider.WriteIntrospectionError(ctx, rw, err)
}

func (w *Wrapper) WriteIntrospectionResponse(ctx context.Context, rw http.ResponseWriter, r fosite.IntrospectionResponder) {
	w.provider.WriteIntrospectionResponse(ctx, rw, r)
}

func (w *Wrapper) NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (fosite.AuthorizeRequester, error) {
	return w.provider.NewPushedAuthorizeRequest(ctx, r)
}

func (w *Wrapper) NewPushedAuthorizeResponse(ctx context.Context, ar fosite.AuthorizeRequester, session fosite.Session) (fosite.PushedAuthorizeResponder, error) {
	return w.provider.NewPushedAuthorizeResponse(ctx, ar, session)
}

func (w *Wrapper) WritePushedAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, ar fosite.AuthorizeRequester, resp fosite.PushedAuthorizeResponder) {
	w.provider.WritePushedAuthorizeResponse(ctx, rw, ar, resp)
}

func (w *Wrapper) WritePushedAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar fosite.AuthorizeRequester, err error) {
	w.provider.WritePushedAuthorizeError(ctx, rw, ar, err)
}
