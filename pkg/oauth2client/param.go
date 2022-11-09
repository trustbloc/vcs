/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client

import (
	"net/url"

	"golang.org/x/oauth2"
)

type setParam struct{ k, v string }

func (p setParam) setValue(m url.Values) { m.Set(p.k, p.v) }

type AuthCodeOption interface {
	setValue(url.Values)
}

func SetAuthURLParam(key, value string) AuthCodeOption {
	return setParam{key, value}
}

func (c *Client) convertOptions(opt ...AuthCodeOption) []oauth2.AuthCodeOption {
	var res []oauth2.AuthCodeOption

	for _, o := range opt {
		res = append(res, oauth2.SetAuthURLParam(o.(setParam).k, o.(setParam).v))
	}

	return res
}
