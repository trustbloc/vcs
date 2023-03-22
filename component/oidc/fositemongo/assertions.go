/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fositemongo

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

func (s *Store) assertInterface() fosite.Storage {
	return s
}

func (s *Store) assertInterface2() oauth2.CoreStorage {
	return s
}

func (s *Store) assertInterface3() oauth2.TokenRevocationStorage {
	return s
}

func (s *Store) assertInterface4() pkce.PKCERequestStorage {
	return s
}

func (s *Store) assertInterface5() fosite.PARStorage {
	return s
}
