/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/trustbloc/did-go/legacy/mem"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	arieskms "github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/local"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/spi/secretlock"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/kms-go/wrapper/localsuite"
	"github.com/trustbloc/kms-go/wrapper/websuite"
	awssvc "github.com/trustbloc/vcs/pkg/kms/aws"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/arieskmsstore"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/key"
	"github.com/trustbloc/vcs/pkg/kms/signer"
)

// nolint: gochecknoglobals
var ariesSupportedKeyTypes = []kmsapi.KeyType{
	kmsapi.ED25519Type,
	kmsapi.X25519ECDHKWType,
	kmsapi.ECDSASecp256k1TypeIEEEP1363,
	kmsapi.ECDSAP256TypeDER,
	kmsapi.ECDSAP384TypeDER,
	kmsapi.RSAPS256Type,
	kmsapi.BLS12381G2Type,
}

// nolint: gochecknoglobals
var awsSupportedKeyTypes = []kmsapi.KeyType{
	kmsapi.ECDSAP256TypeDER,
	kmsapi.ECDSAP384TypeDER,
	kmsapi.ECDSASecp256k1DER,
}

const (
	keystoreLocalPrimaryKeyURI = "local-lock://keystorekms"
	storageTypeMemOption       = "mem"
	storageTypeMongoDBOption   = "mongodb"
)

type metricsProvider interface {
	SignTime(value time.Duration)
}

type KeyManager struct {
	kmsType Type
	metrics metricsProvider
	suite   api.Suite
}

func GetAriesKeyManager(suite api.Suite, kmsType Type, metrics metricsProvider) *KeyManager {
	return &KeyManager{
		suite:   suite,
		kmsType: kmsType,
		metrics: metrics,
	}
}

func NewAriesKeyManager(cfg *Config, metrics metricsProvider) (*KeyManager, error) {
	switch cfg.KMSType {
	case Local:
		suite, err := createLocalKMS(cfg)
		if err != nil {
			return nil, err
		}

		return &KeyManager{
			kmsType: cfg.KMSType,
			metrics: metrics,
			suite:   suite,
		}, nil
	case Web:
		return &KeyManager{
			kmsType: cfg.KMSType,
			metrics: metrics,
			suite:   websuite.NewWebCryptoSuite(cfg.Endpoint, cfg.HTTPClient),
		}, nil
	case AWS:
		awsConfig, err := config.LoadDefaultConfig(
			context.Background(),
			config.WithEndpointResolverWithOptions(prepareResolver(cfg.Endpoint, cfg.Region)),
		)
		if err != nil {
			return nil, err
		}

		awsSuite := awssvc.NewSuite(&awsConfig, nil, "", awssvc.WithKeyAliasPrefix(cfg.AliasPrefix))

		return &KeyManager{
			kmsType: cfg.KMSType,
			metrics: metrics,
			suite:   awsSuite,
		}, nil
	}

	return nil, fmt.Errorf("unsupported kms type: %s", cfg.KMSType)
}

func prepareResolver(endpoint string, reg string) aws.EndpointResolverWithOptionsFunc {
	return func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if endpoint != "" && service == kms.ServiceID && region == reg {
			return aws.Endpoint{
				URL:           endpoint,
				SigningRegion: reg,
			}, nil
		}
		return aws.Endpoint{SigningRegion: reg}, &aws.EndpointNotFoundError{}
	}
}

func createLocalKMS(cfg *Config) (api.Suite, error) {
	secretLockService, err := createLocalSecretLock(cfg.SecretLockKeyPath)
	if err != nil {
		return nil, err
	}

	kmsStore, err := createStore(cfg.DBType, cfg.DBURL, cfg.DBPrefix)
	if err != nil {
		return nil, err
	}

	return localsuite.NewLocalCryptoSuite(keystoreLocalPrimaryKeyURI, kmsStore, secretLockService)
}

func (km *KeyManager) SupportedKeyTypes() []kmsapi.KeyType {
	if km.kmsType == AWS {
		return awsSupportedKeyTypes
	}

	return ariesSupportedKeyTypes
}

func (km *KeyManager) Suite() api.Suite {
	return km.suite
}

func (km *KeyManager) CreateJWKKey(keyType kmsapi.KeyType) (string, *jwk.JWK, error) {
	creator, err := km.Suite().KeyCreator()
	if err != nil {
		return "", nil, err
	}

	return key.JWKKeyCreator(creator)(keyType)
}

func (km *KeyManager) CreateCryptoKey(keyType kmsapi.KeyType) (string, interface{}, error) {
	creator, err := km.Suite().RawKeyCreator()
	if err != nil {
		return "", nil, err
	}

	return key.CryptoKeyCreator(creator)(keyType)
}

func (km *KeyManager) NewVCSigner(
	creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	if signatureType == vcsverifiable.BbsBlsSignature2020 {
		fks, err := km.Suite().FixedKeyMultiSigner(creator)
		if err != nil {
			return nil, err
		}

		return signer.NewKMSSignerBBS(fks, signatureType, km.metrics), nil
	}

	fks, err := km.Suite().FixedKeySigner(creator)
	if err != nil {
		return nil, err
	}

	return signer.NewKMSSigner(fks, signatureType, km.metrics), nil
}

func createLocalSecretLock(keyPath string) (secretlock.Service, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("no key defined for local secret lock")
	}

	primaryKeyReader, err := local.MasterKeyFromPath(keyPath)
	if err != nil {
		return nil, err
	}

	secretLock, err := local.NewService(primaryKeyReader, nil)
	if err != nil {
		return nil, err
	}

	return secretLock, nil
}

func createStore(typ, url, prefix string) (kmsapi.Store, error) {
	switch {
	case strings.EqualFold(typ, storageTypeMemOption):
		return arieskms.NewAriesProviderWrapper(mem.NewProvider())
	case strings.EqualFold(typ, storageTypeMongoDBOption):
		mongoClient, err := mongodb.New(url, prefix)
		if err != nil {
			return nil, err
		}

		return arieskmsstore.NewStore(mongoClient), nil
	default:
		return nil, fmt.Errorf("not supported database type: %s", typ)
	}
}
