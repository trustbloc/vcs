/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package healthchecks_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/component/healthchecks"
)

func TestGet(t *testing.T) {
	require.Len(t, healthchecks.Get(&healthchecks.Config{
		RedisParameters: &healthchecks.RedisParameters{
			Addrs: []string{"redis.example.com"},
		},
	}), 2)
}
