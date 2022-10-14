/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package tls_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/internal/pkg/utils/tls"
)

const (
	tlsCaOrg1 = `-----BEGIN CERTIFICATE-----
MIICSDCCAe+gAwIBAgIQVy95bDHyGiHPiW/hN7iCEzAKBggqhkjOPQQDAjB2MQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEfMB0GA1UEAxMWdGxz
Y2Eub3JnMS5leGFtcGxlLmNvbTAeFw0xODA3MjUxNDQxMjJaFw0yODA3MjIxNDQx
MjJaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRkwFwYDVQQKExBvcmcxLmV4YW1wbGUuY29tMR8wHQYD
VQQDExZ0bHNjYS5vcmcxLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEMl8XK0Rpr514HXVut0MS/PX07l7gWeXGCQkl8T8LBuuSjGEkgSIuOwpf
VqQv4TwXH0A8zIBrtxY2/W3/ERhhC6NfMF0wDgYDVR0PAQH/BAQDAgGmMA8GA1Ud
JQQIMAYGBFUdJQAwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQg+tqYPgAj39pQ
2EH0hxR4SbPOmDRCmwiDsaVIj7tXIFYwCgYIKoZIzj0EAwIDRwAwRAIgUJVxM/57
1WMfcy56D2zw6g9APP5Z3g+Qg/Y5cScstkgCIBj0JVuemNxiQWdXZ/Qhc6sh4m5d
ngzYatfQtNv3/+4V
-----END CERTIFICATE-----`
)

func TestGetCertPool(t *testing.T) {
	t.Run("test wrong file path", func(t *testing.T) {
		certPool, err := tls.GetCertPool(false, []string{"wrongLocation"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read cert")
		require.Nil(t, certPool)
	})

	t.Run("test error from decode pem", func(t *testing.T) {
		file, err := os.CreateTemp("", "file")
		require.NoError(t, err)

		_, err = file.Write([]byte("data"))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		certPool, err := tls.GetCertPool(false, []string{file.Name()})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode pem")
		require.Nil(t, certPool)
	})

	t.Run("test error from success", func(t *testing.T) {
		file, err := os.CreateTemp("", "file")
		require.NoError(t, err)

		_, err = file.Write([]byte(tlsCaOrg1))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()
		certPool, err := tls.GetCertPool(false, []string{file.Name()})
		require.NoError(t, err)
		require.NotNil(t, certPool)
	})
}
