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
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	arieskms "github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/webkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
	awssvc "github.com/trustbloc/kms/pkg/aws"
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

type keyManager interface {
	Get(keyID string) (interface{}, error)
	CreateAndExportPubKeyBytes(kt kmsapi.KeyType, opts ...kmsapi.KeyOpts) (string, []byte, error)
}

type Crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
	SignMulti(messages [][]byte, kh interface{}) ([]byte, error)
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
}

type metricsProvider interface {
	SignTime(value time.Duration)
}

type KeyManager struct {
	keyManager keyManager
	crypto     Crypto
	kmsType    Type
	metrics    metricsProvider
}

func GetAriesKeyManager(keyManager keyManager, crypto Crypto, kmsType Type, metrics metricsProvider) *KeyManager {
	return &KeyManager{
		keyManager: keyManager,
		crypto:     crypto,
		kmsType:    kmsType,
		metrics:    metrics,
	}
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
		awsConfig, err := config.LoadDefaultConfig(
			context.Background(),
			config.WithEndpointResolverWithOptions(prepareResolver(cfg.Endpoint, cfg.Region)),
		)
		if err != nil {
			return nil, err
		}

		awsSvc := awssvc.New(&awsConfig, nil, "", awssvc.WithKeyAliasPrefix(cfg.AliasPrefix))

		return &KeyManager{
			kmsType:    cfg.KMSType,
			keyManager: awsSvc,
			crypto:     awsSvc,
			metrics:    metrics,
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

func createLocalKMS(cfg *Config) (keyManager, Crypto, error) {
	secretLockService, err := createLocalSecretLock(cfg.SecretLockKeyPath)
	if err != nil {
		return nil, nil, err
	}

	kmsStore, err := createStore(cfg.DBType, cfg.DBURL, cfg.DBPrefix)
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

func (km *KeyManager) SupportedKeyTypes() []kmsapi.KeyType {
	if km.kmsType == AWS {
		return awsSupportedKeyTypes
	}

	return ariesSupportedKeyTypes
}

func (km *KeyManager) Crypto() Crypto {
	return km.crypto
}

func (km *KeyManager) CreateJWKKey(keyType kmsapi.KeyType) (string, *jwk.JWK, error) {
	return key.JWKKeyCreator(keyType)(km.keyManager)
}

func (km *KeyManager) CreateCryptoKey(keyType kmsapi.KeyType) (string, interface{}, error) {
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

type kmsProvider struct {
	storageProvider   kmsapi.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kmsapi.Store {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
