/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/vcs/pkg/kms/key"
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

const (
	keystoreLocalPrimaryKeyURI = "local-lock://keystorekms"
	storageTypeMemOption       = "mem"
	storageTypeMongoDBOption   = "mongodb"
)

type LocalKeyManager struct {
	local kms.KeyManager
}

func NewLocalKeyManager(cfg *Config) (*LocalKeyManager, error) {
	secretLockService, err := createLocalSecretLock(cfg.SecretLockKeyPath)
	if err != nil {
		return nil, err
	}

	storeProvider, err := createStoreProvider(cfg.DBType, cfg.DBURL, cfg.DBPrefix)
	if err != nil {
		return nil, err
	}

	kmsStore, err := kms.NewAriesProviderWrapper(storeProvider)
	if err != nil {
		return nil, err
	}

	kmsProv := kmsProvider{
		storageProvider:   kmsStore,
		secretLockService: secretLockService,
	}

	localKms, err := localkms.New(keystoreLocalPrimaryKeyURI, kmsProv)
	if err != nil {
		return nil, err
	}

	return &LocalKeyManager{
		local: localKms,
	}, nil
}

func (km *LocalKeyManager) SupportedKeyTypes() []kms.KeyType {
	return ariesSupportedKeyTypes
}

func (km *LocalKeyManager) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	return key.JWKKeyCreator(keyType)(km.local)
}

func (km *LocalKeyManager) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	return key.CryptoKeyCreator(keyType)(km.local)
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
