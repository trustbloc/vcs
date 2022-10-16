/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package tls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"

	commontls "github.com/trustbloc/vcs/internal/pkg/tls"
)

// GetCertPool get cert pool.
func GetCertPool(useSystemCertPool bool, tlsCACerts []string) (*x509.CertPool, error) {
	certPool, err := commontls.NewCertPool(useSystemCertPool)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cert pool: %w", err)
	}

	for _, v := range tlsCACerts {
		bytes, errRead := os.ReadFile(path.Clean(v))
		if errRead != nil {
			return nil, fmt.Errorf("failed to read cert: %w", errRead)
		}

		block, _ := pem.Decode(bytes)
		if block == nil {
			return nil, fmt.Errorf("failed to decode pem")
		}

		cert, errParse := x509.ParseCertificate(block.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("failed to parse cert: %w", errParse)
		}

		certPool.Add(cert)
	}

	return certPool.Get()
}
