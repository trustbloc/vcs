/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import profileapi "github.com/trustbloc/vcs/pkg/profile"

var createdIssuers = map[string]*profileapi.Issuer{} // nolint:gochecknoglobals
