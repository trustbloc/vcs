/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	Args map[string]string
}

// NewBDDContext create new BDDContext
func NewBDDContext() (*BDDContext, error) {
	instance := BDDContext{
		Args: make(map[string]string),
	}

	return &instance, nil
}
