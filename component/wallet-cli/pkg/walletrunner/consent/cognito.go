/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package consent

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Cognito struct {
	httpClient      httpClient
	url             string
	password        string
	login           string
	existingCookies map[string]*http.Cookie
}

func NewCognito(client httpClient, cookies []*http.Cookie, url string, login string, password string) *Cognito {
	existing := map[string]*http.Cookie{}
	for _, c := range cookies {
		existing[c.Name] = c
	}

	return &Cognito{
		url:             url,
		existingCookies: existing,
		httpClient:      client,
		login:           login,
		password:        password,
	}
}

func (c *Cognito) Execute() error {
	getReq, err := http.NewRequest(http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}

	getResp, err := c.httpClient.Do(getReq)
	if err != nil {
		return err
	}

	data := url.Values{}
	data.Set("username", c.login)
	data.Set("password", c.password)
	data.Add("signInSubmitButton", "Sign in")

	for _, cookie := range getResp.Cookies() {
		c.existingCookies[cookie.Name] = cookie
	}

	xsrf, ok := c.existingCookies["XSRF-TOKEN"]
	if !ok {
		return errors.New("XSRF-TOKEN cookie not found")
	}

	data.Add("_csrf", xsrf.Value)

	postReq, err := http.NewRequest(http.MethodPost, c.url, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	for _, cookie := range c.existingCookies {
		postReq.AddCookie(cookie)
	}

	postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	postResp, postErr := c.httpClient.Do(postReq)
	if postErr != nil {
		return postErr
	}

	if postResp.StatusCode != http.StatusFound {
		var body []byte
		if postResp.Body != nil {
			body, _ = io.ReadAll(postResp.Body)
			defer func() {
				_ = postResp.Body.Close()
			}()
		}

		return fmt.Errorf("unexpected status code from post cognito. %v with body %s",
			postResp.StatusCode, body)
	}

	return nil
}
