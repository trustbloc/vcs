/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	awssvc "github.com/trustbloc/kms/pkg/aws"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms/key"
	"github.com/trustbloc/vcs/pkg/kms/signer"
)

// nolint: gochecknoglobals
var ariesSupportedKeyTypes = []kms.KeyType{
	kms.ED25519Type,
	kms.X25519ECDHKWType,
	kms.ECDSASecp256k1TypeIEEEP1363,
	kms.ECDSAP256TypeDER,
	kms.ECDSAP384TypeDER,
	kms.RSAPS256Type,
	kms.BLS12381G2Type,
}

// nolint: gochecknoglobals
var awsSupportedKeyTypes = []kms.KeyType{
	kms.ECDSAP256TypeDER,
	kms.ECDSAP384TypeDER,
	kms.ECDSASecp256k1DER,
}

const (
	keystoreLocalPrimaryKeyURI = "local-lock://keystorekms"
	storageTypeMemOption       = "mem"
	storageTypeMongoDBOption   = "mongodb"
)

type keyManager interface {
	Get(keyID string) (interface{}, error)
	CreateAndExportPubKeyBytes(kt kms.KeyType, opts ...kms.KeyOpts) (string, []byte, error)
}

type crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
	SignMulti(messages [][]byte, kh interface{}) ([]byte, error)
}

type metricsProvider interface {
	SignTime(value time.Duration)
}

type KeyManager struct {
	keyManager keyManager
	crypto     crypto
	kmsType    Type
	metrics    metricsProvider
}

func NewAriesKeyManager(cfg *Config, metrics metricsProvider) (*KeyManager, error) {
	switch cfg.KMSType {
	case Local:
		km, cr, err := createLocalKMS(cfg)
		if err != nil {
			return nil, err
		}

		return &KeyManager{
			kmsType:    cfg.KMSType,
			keyManager: km,
			crypto:     cr,
			metrics:    metrics,
		}, nil
	case Web:
		return &KeyManager{
			kmsType:    cfg.KMSType,
			keyManager: webkms.New(cfg.Endpoint, cfg.HTTPClient),
			crypto:     webcrypto.New(cfg.Endpoint, cfg.HTTPClient),
			metrics:    metrics,
		}, nil
	case AWS:
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &cfg.Endpoint,
			Region:                        aws.String(cfg.Region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		if err != nil {
			return nil, err
		}

		awsSvc := awssvc.New(awsSession, nil, "", awssvc.WithKeyAliasPrefix("vcs"))

		return &KeyManager{
			kmsType:    cfg.KMSType,
			keyManager: awsSvc,
			crypto:     awsSvc,
			metrics:    metrics,
		}, nil
	}

	return nil, fmt.Errorf("unsupported kms type: %s", cfg.KMSType)
}

func createLocalKMS(cfg *Config) (keyManager, crypto, error) {
	secretLockService, err := createLocalSecretLock(cfg.SecretLockKeyPath)
	if err != nil {
		return nil, nil, err
	}

	storeProvider, err := createStoreProvider(cfg.DBType, cfg.DBURL, cfg.DBPrefix)
	if err != nil {
		return nil, nil, err
	}

	kmsStore, err := kms.NewAriesProviderWrapper(storeProvider)
	if err != nil {
		return nil, nil, err
	}

	kmsProv := kmsProvider{
		storageProvider:   kmsStore,
		secretLockService: secretLockService,
	}

	localKms, err := localkms.New(keystoreLocalPrimaryKeyURI, kmsProv)
	if err != nil {
		return nil, nil, err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, nil, err
	}

	return localKms, crypto, nil
}

func (km *KeyManager) SupportedKeyTypes() []kms.KeyType {
	if km.kmsType == AWS {
		return awsSupportedKeyTypes
	}

	return ariesSupportedKeyTypes
}

func (km *KeyManager) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	return key.JWKKeyCreator(keyType)(km.keyManager)
}

func (km *KeyManager) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	return key.CryptoKeyCreator(keyType)(km.keyManager)
}

func (km *KeyManager) NewVCSigner(
	creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	return signer.NewKMSSigner(km.keyManager, km.crypto, creator, signatureType, km.metrics)
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

func createStoreProvider(typ, url, prefix string) (storage.Provider, error) {
	var createProvider func(url, prefix string) (storage.Provider, error)

	switch {
	case strings.EqualFold(typ, storageTypeMemOption):
		createProvider = func(string, string) (storage.Provider, error) { //nolint:unparam
			return mem.NewProvider(), nil
		}

	case strings.EqualFold(typ, storageTypeMongoDBOption):
		createProvider = func(url, prefix string) (storage.Provider, error) {
			mongoDBProvider, err := mongodb.NewProvider(url, mongodb.WithDBPrefix(prefix))
			if err != nil {
				return nil, err
			}

			return mongoDBProvider, nil
		}
	default:
		return nil, fmt.Errorf("not supported database type: %s", typ)
	}

	return createProvider(url, prefix)
}

type kmsProvider struct {
	storageProvider   kms.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kms.Store {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
