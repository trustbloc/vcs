/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	tlsutils "github.com/trustbloc/cmdutil-go/pkg/utils/tls"

	"github.com/trustbloc/vcs/pkg/profile"
)

const (
	didResolverURL = "http://localhost:8072/1.0/identifiers"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	Args                  map[string]string
	CreatedCredential     []byte // Holds either issued JWT and LSON-LD VC.
	CreatedCredentialsSet [][]byte
	VDRI                  vdrapi.Registry
	TLSConfig             *tls.Config
	TestData              map[string][]byte
	Data                  map[string]interface{}
	CredentialSubject     []string
	IssuerProfiles        map[string]*profile.Issuer
	VerifierProfiles      map[string]*profile.Verifier
}

type profilesFileData struct {
	Issuers   []*issuerRecord   `json:"issuers"`
	Verifiers []*verifierRecord `json:"verifiers"`
}

type issuerRecord struct {
	Issuer              *profile.Issuer `json:"issuer"`
	CreateDID           bool            `json:"createDID"`
	DIDDomain           string          `json:"didDomain"`
	DIDServiceAuthToken string          `json:"didServiceAuthToken"`
}

type verifierRecord struct {
	Verifier *profile.Verifier `json:"verifier"`
}

// NewBDDContext create new BDDContext
func NewBDDContext(caCertPath, testDataPath, profilesDataPath string) (*BDDContext, error) {
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

	files, err := os.ReadDir(testDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test data directory: %w", err)
	}

	for _, file := range files {
		testData[file.Name()], err = os.ReadFile(filepath.Join(testDataPath, file.Name())) //nolint: gosec
		if err != nil {
			return nil, fmt.Errorf("failed to read tesdata '%s' : %w", file.Name(), err)
		}
	}

	b, err := os.ReadFile(profilesDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles data file: %w", err)
	}

	var profilesData profilesFileData

	if err = json.Unmarshal(b, &profilesData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profiles data: %w", err)
	}

	issuerProfiles := make(map[string]*profile.Issuer)

	for _, issuer := range profilesData.Issuers {
		issuerProfiles[fmt.Sprintf("%s/%s", issuer.Issuer.ID, issuer.Issuer.Version)] = issuer.Issuer
	}

	verifierProfiles := make(map[string]*profile.Verifier)

	for _, verifier := range profilesData.Verifiers {
		verifierProfiles[fmt.Sprintf("%s/%s", verifier.Verifier.ID, verifier.Verifier.Version)] = verifier.Verifier
	}

	instance := BDDContext{
		Args:             make(map[string]string),
		VDRI:             vdr,
		TLSConfig:        tlsConf,
		TestData:         testData,
		Data:             make(map[string]interface{}),
		IssuerProfiles:   issuerProfiles,
		VerifierProfiles: verifierProfiles,
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
