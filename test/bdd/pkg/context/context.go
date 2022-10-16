/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"

	tlsutils "github.com/trustbloc/vcs/internal/pkg/utils/tls"
	vcsstorage "github.com/trustbloc/vcs/pkg/storage"
)

const (
	didResolverURL = "http://localhost:8072/1.0/identifiers"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	Args                  map[string]string
	CreatedCredential     []byte
	CreatedCredentialsSet [][]byte
	CreatedProfile        *vcsstorage.IssuerProfile
	VDRI                  vdrapi.Registry
	TLSConfig             *tls.Config
	TestData              map[string][]byte
	Data                  map[string]interface{}
}

// NewBDDContext create new BDDContext
func NewBDDContext(caCertPath, testDataPath string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPath})
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	vdr, err := createVDRI(didResolverURL, tlsConf)
	if err != nil {
		return nil, err
	}

	testData := make(map[string][]byte)

	files, err := ioutil.ReadDir(testDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test data directory: %w", err)
	}

	for _, file := range files {
		testData[file.Name()], err = ioutil.ReadFile(filepath.Join(testDataPath, file.Name())) //nolint: gosec
		if err != nil {
			return nil, fmt.Errorf("failed to read tesdata '%s' : %w", file.Name(), err)
		}
	}

	instance := BDDContext{
		Args:      make(map[string]string),
		VDRI:      vdr,
		TLSConfig: tlsConf,
		TestData:  testData,
		Data:      make(map[string]interface{}),
	}

	return &instance, nil
}

func createVDRI(didResolverURL string, tlsConf *tls.Config) (vdrapi.Registry, error) {
	didResolverVDRI, err := httpbinding.New(didResolverURL,
		httpbinding.WithAccept(func(method string) bool {
			return method == "v1" || method == "elem" || method == "sov" ||
				method == "web" || method == "key" || method == "factom"
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to create new universal resolver vdr: %w", err)
	}

	blocVDR, err := orb.New(nil, orb.WithTLSConfig(tlsConf),
		orb.WithDomain("testnet.orb.local"))
	if err != nil {
		return nil, err
	}

	return vdrpkg.New(vdrpkg.WithVDR(blocVDR), vdrpkg.WithVDR(didResolverVDRI)), nil
}
