/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requestobject

import (
	"errors"
)

type RequestObject struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

var ErrDataNotFound = errors.New("data not found")
