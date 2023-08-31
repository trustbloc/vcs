package walletrunner

import (
	"context"
	"net/http"
)

type httpClientKey = struct{}

func WithHttpClient(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, httpClientKey{}, client)
}

func HttpClientFromContext(ctx context.Context, fallback *http.Client) *http.Client {
	val := ctx.Value(httpClientKey{})
	if val != nil {
		return val.(*http.Client)
	}

	return fallback
}
