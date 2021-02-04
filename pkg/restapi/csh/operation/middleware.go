/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

const (
	actionRead      = "read"
	actionWrite     = "write"
	actionReference = "reference"
)

func allActions() []string {
	return []string{
		actionRead,
		actionWrite,
		actionReference,
	}
}
