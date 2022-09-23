/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidctxstore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-redis/redis/v8"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/storage/redis/oidctxstore"
)

const (
	redisDBHost        = "localhost:6379"
	dockerRedisDBImage = "redis"
	dockerRedisDBTag   = "7.0.4"
)

type testStruct struct {
	StrFld string `json:"strFld"`
	IntFld int    `json:"intFld"`
}

func TestTxStore_Success(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)
	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	store := oidctxstore.New(createRedisClient(), 10*time.Second)

	t.Run("Set not exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key", []byte("value"), 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)
	})

	t.Run("Set exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key2", []byte("value"), 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		isSet, err = store.SetIfNotExist("key2", []byte("value"), 10*time.Second)
		require.False(t, isSet)
		require.NoError(t, err)
	})

	t.Run("Get not exist", func(t *testing.T) {
		_, exists, err := store.GetAndDelete("key3")

		require.False(t, exists)
		require.NoError(t, err)
	})

	t.Run("Get exist", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key3", []byte("value"), 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("key3")

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, []byte("value"), data)
	})

	t.Run("Get exist and check if deleted", func(t *testing.T) {
		isSet, err := store.SetIfNotExist("key3", []byte("value"), 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("key3")

		require.True(t, exists)
		require.NoError(t, err)
		require.Equal(t, []byte("value"), data)

		_, exists, err = store.GetAndDelete("key3")

		require.False(t, exists)
		require.NoError(t, err)
	})

	t.Run("test json payload", func(t *testing.T) {
		val, err := json.Marshal(&testStruct{
			StrFld: "testStr",
			IntFld: 10,
		})
		require.NoError(t, err)

		isSet, err := store.SetIfNotExist("struct", val, 10*time.Second)
		require.True(t, isSet)
		require.NoError(t, err)

		data, exists, err := store.GetAndDelete("struct")
		require.True(t, exists)
		require.NoError(t, err)

		tstStrct := &testStruct{}

		err = json.Unmarshal(data, tstStrct)
		require.NoError(t, err)

		require.Equal(t, "testStr", tstStrct.StrFld)
		require.Equal(t, 10, tstStrct.IntFld)
	})
}

func TestTxStore_ConnectoinFail(t *testing.T) {
	store := oidctxstore.New(createRedisClient(), 10*time.Second)

	t.Run("Set fail", func(t *testing.T) {
		_, err := store.SetIfNotExist("key", []byte("value"), 10*time.Second)
		require.Contains(t, err.Error(), "connection refused")
	})

	t.Run("Get fail", func(t *testing.T) {
		_, _, err := store.GetAndDelete("key")
		require.Contains(t, err.Error(), "connection refused")
	})
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerRedisDBImage,
		Tag:        dockerRedisDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"6379/tcp": {{HostIP: "", HostPort: "6379"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForRedisDBToBeUp())

	return pool, mongoDBResource
}

func waitForRedisDBToBeUp() error {
	return backoff.Retry(pingMongoDB, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func createRedisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     redisDBHost,
		Password: "", // no password set
		DB:       0,
	})
}

func pingMongoDB() error {
	client := createRedisClient()

	_, err := client.Ping(context.Background()).Result()

	client.Close()

	return err
}
