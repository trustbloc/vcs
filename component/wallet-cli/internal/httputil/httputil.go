/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httputil

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
)

// HTTPSDo send https request
func HTTPSDo(method, url, contentType, token string, body io.Reader, tlsConfig *tls.Config) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	return c.Do(req)
}

// CloseResponseBody closes the response body.
func CloseResponseBody(respBody io.Closer) {
	err := respBody.Close()
	if err != nil {
		log.Println("Failed to close response body", err)
	}
}
