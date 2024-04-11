/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package stress

import "net/http"

type mitmTransport struct {
	root               http.RoundTripper
	requestInterceptor func(request *http.Request, parent http.RoundTripper) (*http.Response, error)
}

func (m *mitmTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return m.requestInterceptor(request, m.root)
}
