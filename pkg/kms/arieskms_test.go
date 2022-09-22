/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/kms"
)

const (
	mongoDBConnString  = "mongodb://localhost:27020"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

// nolint: gochecknoglobals
var secretLockKeyFile string

func TestNewLocalKeyManager(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		km, err := kms.NewLocalKeyManager(&kms.Config{
			KMSType:           kms.Local,
			SecretLockKeyPath: secretLockKeyFile,
			DBType:            "mem",
			DBURL:             "",
			DBPrefix:          "",
		})

		require.NotNil(t, km)
		require.NoError(t, err)

		require.Contains(t, km.SupportedKeyTypes(), arieskms.ED25519Type)

		jwkID, jwk, err := km.CreateJWKKey(arieskms.ED25519Type)

		require.NotEmpty(t, jwkID)
		require.NotNil(t, jwk)
		require.NoError(t, err)

		cryptoKeyID, cryptoKey, err := km.CreateCryptoKey(arieskms.ED25519Type)

		require.NotEmpty(t, cryptoKeyID)
		require.NotNil(t, cryptoKey)
		require.NoError(t, err)
	})

	t.Run("Success mongodb", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		km, err := kms.NewLocalKeyManager(&kms.Config{
			KMSType:           kms.Local,
			SecretLockKeyPath: secretLockKeyFile,
			DBType:            "mongodb",
			DBURL:             mongoDBConnString,
			DBPrefix:          "test",
		})

		require.NotNil(t, km)
		require.NoError(t, err)
	})

	t.Run("Incorrect SecretLockKeyPath", func(t *testing.T) {
		_, err := kms.NewLocalKeyManager(&kms.Config{
			KMSType:           kms.Local,
			SecretLockKeyPath: "incorrect",
			DBType:            "mem",
			DBURL:             "",
			DBPrefix:          "",
		})

		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("Incorrect db type", func(t *testing.T) {
		_, err := kms.NewLocalKeyManager(&kms.Config{
			KMSType:           kms.Local,
			SecretLockKeyPath: secretLockKeyFile,
			DBType:            "incorrect",
			DBURL:             "",
			DBPrefix:          "",
		})

		require.Contains(t, err.Error(), "not supported database type")
	})
}

func TestMain(m *testing.M) {
	file, closeFunc := createSecretLockKeyFile()
	secretLockKeyFile = file

	code := m.Run()

	closeFunc()
	os.Exit(code)
}

func createSecretLockKeyFile() (string, func()) {
	f, err := ioutil.TempFile("", "secret-lock.key")
	if err != nil {
		panic(err)
	}

	closeFunc := func() {
		if closeErr := f.Close(); closeErr != nil {
			panic(closeErr)
		}

		if removeErr := os.Remove(f.Name()); removeErr != nil {
			panic(removeErr)
		}
	}

	key := make([]byte, sha256.Size)
	_, err = rand.Read(key)
	if err != nil {
		panic(err)
	}

	encodedKey := make([]byte, base64.URLEncoding.EncodedLen(len(key)))
	base64.URLEncoding.Encode(encodedKey, key)

	_, err = f.Write(encodedKey)
	if err != nil {
		panic(err)
	}

	return f.Name(), closeFunc
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27020"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp())

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp() error {
	return backoff.Retry(pingMongoDB, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB() error {
	var err error

	tM := reflect.TypeOf(bson.M{})
	reg := bson.NewRegistryBuilder().RegisterTypeMapEntry(bsontype.EmbeddedDocument, tM).Build()
	clientOpts := options.Client().SetRegistry(reg).ApplyURI(mongoDBConnString)

	mongoClient, err := mongo.NewClient(clientOpts)
	if err != nil {
		return err
	}

	err = mongoClient.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	db := mongoClient.Database("test")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return db.Client().Ping(ctx, nil)
}

func TestNewAriesKeyManager(t *testing.T) {
	type args struct {
		localKms arieskms.KeyManager
		crypto   crypto.Crypto
	}
	tests := []struct {
		name string
		args args
		want *kms.LocalKeyManager
	}{
		{
			name: "OK Mocked",
			args: args{
				localKms: &mockkms.KeyManager{},
				crypto:   &mockcrypto.Crypto{},
			},
			want: kms.NewAriesKeyManager(&mockkms.KeyManager{}, &mockcrypto.Crypto{}),
		},
		{
			name: "OK Local",
			args: args{
				localKms: &localkms.LocalKMS{},
				crypto:   &tinkcrypto.Crypto{},
			},
			want: kms.NewAriesKeyManager(&localkms.LocalKMS{}, &tinkcrypto.Crypto{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kms.NewAriesKeyManager(tt.args.localKms, tt.args.crypto); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAriesKeyManager() = %v, want %v", got, tt.want)
			}
		})
	}
}
