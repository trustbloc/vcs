/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vc

import "time"

type metric struct {
	Name string
	Avg  time.Duration
	Max  time.Duration
	Min  time.Duration
}
