/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"

	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
)

// Config contain config
type Config struct {
	ProfileJSONFile string
	KMSRegistry     *vcskms.Registry
	TLSConfig       *tls.Config
}

// IssuerReader read issuer profiles.
type IssuerReader struct {
	issuers   map[string]*profileapi.Issuer
	verifiers map[string]*profileapi.Verifier
}

// VerifierReader read verifier profiles.
type VerifierReader struct {
	issuers   map[string]*profileapi.Issuer
	verifiers map[string]*profileapi.Verifier
}

type profile struct {
	IssuersData   []*issuerProfile   `json:"issuers"`
	VerifiersData []*verifierProfile `json:"verifiers"`
}

type issuerProfile struct {
	Data                *profileapi.Issuer `json:"issuer,omitempty"`
	CreateDID           bool               `json:"createDID"`
	DidDomain           string             `json:"didDomain"`
	DidServiceAuthToken string             `json:"didServiceAuthToken"`
}

type verifierProfile struct {
	Data                *profileapi.Verifier `json:"verifier,omitempty"`
	CreateDID           bool                 `json:"createDID"`
	DidDomain           string               `json:"didDomain"`
	DidServiceAuthToken string               `json:"didServiceAuthToken"`
}

// NewIssuerReader creates issuer Reader.
func NewIssuerReader(config *Config) (*IssuerReader, error) {
	if config.ProfileJSONFile == "" {
		return nil, nil
	}

	r := IssuerReader{issuers: make(map[string]*profileapi.Issuer)}

	jsonBytes, err := os.ReadFile(filepath.Clean(config.ProfileJSONFile))
	if err != nil {
		return nil, err
	}

	var p profile
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, err
	}

	for _, v := range p.IssuersData {
		if v.CreateDID {
			vdr, err := orb.New(nil, orb.WithDomain(v.DidDomain), orb.WithTLSConfig(config.TLSConfig),
				orb.WithAuthToken(v.DidServiceAuthToken))
			if err != nil {
				return nil, err
			}

			didCreator := newCreator(&creatorConfig{vdr: vdrpkg.New(vdrpkg.WithVDR(vdr))})

			keyCreator, err := config.KMSRegistry.GetKeyManager(v.Data.KMSConfig)
			if err != nil {
				return nil, fmt.Errorf("issuer profile service: create profile failed: get keyCreator %w", err)
			}

			createResult, err := didCreator.publicDID(v.Data.VCConfig.DIDMethod,
				v.Data.VCConfig.SigningAlgorithm, v.Data.VCConfig.KeyType, keyCreator)
			if err != nil {
				return nil, fmt.Errorf("issuer profile service: create profile failed: create did %w", err)
			}

			v.Data.SigningDID = &profileapi.SigningDID{
				DID:            createResult.didID,
				Creator:        createResult.creator,
				UpdateKeyURL:   createResult.updateKeyURL,
				RecoveryKeyURL: createResult.recoveryKeyURL,
			}
		}

		r.issuers[v.Data.ID] = v.Data
	}

	return &r, nil
}

// GetProfile returns profile with given id.
func (p *IssuerReader) GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error) {
	return p.issuers[profileID], nil
}

// GetAllProfiles returns all profiles with given organization id.
func (p *IssuerReader) GetAllProfiles(orgID string) ([]*profileapi.Issuer, error) {
	return nil, nil
}

// NewVerifiersReader creates verifier Reader.
func NewVerifiersReader(config *Config) (*VerifierReader, error) {
	if config.ProfileJSONFile == "" {
		return nil, nil
	}

	r := VerifierReader{
		verifiers: make(map[string]*profileapi.Verifier),
	}

	jsonBytes, err := os.ReadFile(filepath.Clean(config.ProfileJSONFile))
	if err != nil {
		return nil, err
	}

	var p profile
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, err
	}

	for _, v := range p.VerifiersData {
		if v.Data.OIDCConfig != nil && v.CreateDID {
			vdr, err := orb.New(nil, orb.WithDomain(v.DidDomain), orb.WithTLSConfig(config.TLSConfig),
				orb.WithAuthToken(v.DidServiceAuthToken))
			if err != nil {
				return nil, err
			}

			didCreator := newCreator(&creatorConfig{vdr: vdrpkg.New(vdrpkg.WithVDR(vdr))})

			keyCreator, err := config.KMSRegistry.GetKeyManager(v.Data.KMSConfig)
			if err != nil {
				return nil, fmt.Errorf("issuer profile service: create profile failed: get keyCreator %w", err)
			}

			createResult, err := didCreator.publicDID(v.Data.OIDCConfig.DIDMethod,
				v.Data.OIDCConfig.ROSigningAlgorithm, v.Data.OIDCConfig.KeyType, keyCreator)
			if err != nil {
				return nil, fmt.Errorf("issuer profile service: create profile failed: create did %w", err)
			}

			v.Data.SigningDID = &profileapi.SigningDID{
				DID:            createResult.didID,
				Creator:        createResult.creator,
				UpdateKeyURL:   createResult.updateKeyURL,
				RecoveryKeyURL: createResult.recoveryKeyURL,
			}
		}

		r.verifiers[v.Data.ID] = v.Data
	}

	return &r, nil
}

// GetProfile returns profile with given id.
func (p *VerifierReader) GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error) {
	return p.verifiers[profileID], nil
}

// GetAllProfiles returns all profiles with given organization id.
func (p *verifierProfile) GetAllProfiles(orgID string) ([]*profileapi.Verifier, error) {
	return nil, nil
}
