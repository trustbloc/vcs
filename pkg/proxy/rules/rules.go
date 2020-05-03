/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rules

// Provider interface for transforming URLs
type Provider interface {
	Transform(uri string) (string, error)
}
