/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resterr

import (
	"errors"
)

var (
	ErrDataNotFound    = errors.New("data not found")
	ErrProfileInactive = errors.New("profile not active")
	ErrProfileNotFound = errors.New("profile doesn't exist")
)
