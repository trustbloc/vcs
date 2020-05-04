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

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	vdripkg "github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"

	"github.com/trustbloc/edge-service/pkg/doc/vc/profile"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	Args              map[string]string
	CreatedCredential []byte
	CreatedProfile    *profile.DataProfile
	VDRI              vdriapi.Registry
	TLSConfig         *tls.Config
	TestData          map[string][]byte
	Data              map[string]interface{}
}

// NewBDDContext create new BDDContext
func NewBDDContext(caCertPath, testDataPath string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPath})
	if err != nil {
		return nil, err
	}

	vdri, err := createVDRI("http://localhost:8080/1.0/identifiers")
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
		VDRI:      vdri,
		TLSConfig: &tls.Config{RootCAs: rootCAs},
		TestData:  testData,
		Data:      make(map[string]interface{}),
	}

	return &instance, nil
}

func createVDRI(universalResolver string) (vdriapi.Registry, error) {
	universalResolverVDRI, err := httpbinding.New(universalResolver,
		httpbinding.WithAccept(func(method string) bool {
			return method == "v1" || method == "elem" || method == "sov" ||
				method == "web" || method == "key"
		}))
	if err != nil {
		return nil, fmt.Errorf("failed to create new universal resolver vdri: %w", err)
	}

	vdriProvider, err := context.New(context.WithLegacyKMS(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create new vdri provider: %w", err)
	}

	return vdripkg.New(vdriProvider, vdripkg.WithVDRI(trustbloc.New(trustbloc.WithResolverURL(universalResolver))),
		vdripkg.WithVDRI(universalResolverVDRI)), nil
}
