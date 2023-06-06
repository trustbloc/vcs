/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package consent

import "net/http"

//go:generate mockgen -destination interfaces_mocks_test.go -package consent_test -source=interfaces.go
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}
