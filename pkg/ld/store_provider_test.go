/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/golang/mock/gomock"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/ld"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func Test2(t *testing.T) {
	resourceURL := "https://w3c.github.io/vc-data-model/related-resource.json"
	expectedDigest := "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"

	// Fetch the resource
	resp, err := http.Get(resourceURL)
	if err != nil {
		fmt.Println("Error fetching resource:", err)
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)

	//encoded := base64.StdEncoding.EncodeToString(data)

	// Calculate the SHA-256 hash of the resource
	//hasher := sha256.New()
	//if _, err := io.Copy(hasher, resp.Body); err != nil {
	//	fmt.Println("Error reading resource:", err)
	//	return
	//}

	decodedSign, err := base64.StdEncoding.DecodeString("ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356")
	assert.NoError(t, err)

	hasher := sha256.New()
	hasher.Write([]byte(data))

	computedHash := hasher.Sum(nil)
	computedDigest := fmt.Sprintf("%x", computedHash)

	fmt.Println(decodedSign)
	// Validate the digest
	if computedDigest == expectedDigest {
		fmt.Println("Digest validation successful!")
	} else {
		fmt.Println("Digest validation failed.")
		fmt.Printf("Expected: %s\n", expectedDigest)
		fmt.Printf("Computed: %s\n", computedDigest)
	}
}

func TestNewStoreProvider(t *testing.T) {
	connectionString := "mongodb://localhost:27029"

	pool, mongoDBResource := startMongoDBContainer(t, connectionString, "27029")

	t.Cleanup(func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	})

	client, clientErr := mongodb.New(connectionString, "testdb", mongodb.WithTimeout(time.Second*10))
	require.NoError(t, clientErr)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	t.Run("Success", func(t *testing.T) {
		provider, err := ld.NewStoreProvider(client, NewMockCache(gomock.NewController(t)))

		require.NotNil(t, provider)
		require.NoError(t, err)
		require.NotNil(t, provider.JSONLDContextStore())
		require.NotNil(t, provider.JSONLDRemoteProviderStore())
	})
}

func startMongoDBContainer(t *testing.T, connectionString, port string) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: port}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp(connectionString))

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp(connectionString string) error {
	return backoff.Retry(func() error {
		return pingMongoDB(connectionString)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB(connectionString string) error {
	var err error

	clientOpts := options.Client().ApplyURI(connectionString)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mongoClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return err
	}

	db := mongoClient.Database("test")

	return db.Client().Ping(ctx, nil)
}
