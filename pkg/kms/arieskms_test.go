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
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
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
		km, err := kms.NewAriesKeyManager(&kms.Config{
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

		_, err = km.NewVCSigner("did", "EdDSA")
		require.Error(t, err)
		require.Contains(t, err.Error(), "verificationMethod value did should be in did#keyID format")
	})

	t.Run("Success mongodb", func(t *testing.T) {
		pool, mongoDBResource := startMongoDBContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		km, err := kms.NewAriesKeyManager(&kms.Config{
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
		_, err := kms.NewAriesKeyManager(&kms.Config{
			KMSType:           kms.Local,
			SecretLockKeyPath: "incorrect",
			DBType:            "mem",
			DBURL:             "",
			DBPrefix:          "",
		})

		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("Incorrect db type", func(t *testing.T) {
		_, err := kms.NewAriesKeyManager(&kms.Config{
			KMSType:           kms.Local,
			SecretLockKeyPath: secretLockKeyFile,
			DBType:            "incorrect",
			DBURL:             "",
			DBPrefix:          "",
		})

		require.Contains(t, err.Error(), "not supported database type")
	})
}

func TestNewWebKeyManager(t *testing.T) {
	t.Run("wrong endpoint for kms web", func(t *testing.T) {
		km, err := kms.NewAriesKeyManager(&kms.Config{
			KMSType:    kms.Web,
			HTTPClient: &http.Client{},
			Endpoint:   "url",
		})

		require.NotNil(t, km)
		require.NoError(t, err)

		require.Contains(t, km.SupportedKeyTypes(), arieskms.ED25519Type)

		_, _, err = km.CreateJWKKey(arieskms.ED25519Type)

		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol scheme")
	})
}

func TestNewAWSKeyManager(t *testing.T) {
	t.Run("wrong key type for kms aws", func(t *testing.T) {
		km, err := kms.NewAriesKeyManager(&kms.Config{
			KMSType:    kms.AWS,
			HTTPClient: &http.Client{},
			Endpoint:   "url",
		})

		require.NotNil(t, km)
		require.NoError(t, err)

		_, _, err = km.CreateJWKKey(arieskms.ED25519Type)

		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported ED25519")
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
