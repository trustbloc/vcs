/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifierstore_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/verifierstore"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const (
	mongoDBConnString  = "mongodb://localhost:27018"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestProfileStore_Success(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, connErr := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, connErr)

	store := verifierstore.NewProfileStore(client)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create profile", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{
			Name:   "test profile",
			URL:    "https://verifer.example.com",
			Active: true,
			Checks: &verifier.VerificationChecks{
				Credential: &verifier.CredentialChecks{
					Proof: true,
					Format: []verifier.CredentialFormat{
						verifier.JwtVC,
						verifier.LdpVC,
					},
					Status: true,
				},
				Presentation: &verifier.PresentationChecks{
					Proof: true,
					Format: []verifier.PresentationFormat{
						verifier.JwtVP,
						verifier.LdpVP,
					},
				},
			},
			OIDCConfig:     nil,
			OrganizationID: "org1",
		})
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create profile then find by id", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{})

		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
	})

	t.Run("Create profile then find by id", func(t *testing.T) {
		_, err := store.Create(&verifier.Profile{OrganizationID: "test1"})
		require.NoError(t, err)

		_, err = store.Create(&verifier.Profile{OrganizationID: "test1"})
		require.NoError(t, err)

		_, err = store.Create(&verifier.Profile{OrganizationID: "test2"})
		require.NoError(t, err)

		profiles, err := store.FindByOrgID("test1")
		require.NoError(t, err)
		require.Len(t, profiles, 2)
	})

	t.Run("Update profile", func(t *testing.T) {
		checks := &verifier.VerificationChecks{
			Credential: &verifier.CredentialChecks{
				Proof: true,
				Format: []verifier.CredentialFormat{
					verifier.JwtVC,
					verifier.LdpVC,
				},
				Status: true,
			},
			Presentation: &verifier.PresentationChecks{
				Proof: true,
				Format: []verifier.PresentationFormat{
					verifier.JwtVP,
					verifier.LdpVP,
				},
			},
		}

		id, err := store.Create(&verifier.Profile{
			Name:           "test profile",
			URL:            "https://verifer.example.com",
			Active:         true,
			Checks:         checks,
			OIDCConfig:     nil,
			OrganizationID: "org1",
		})
		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.Equal(t, "test profile", profile.Name)
		require.Equal(t, id, profile.ID)

		checks.Credential.Format = []verifier.CredentialFormat{verifier.LdpVC}
		checks.Presentation.Format = []verifier.PresentationFormat{verifier.LdpVP}

		err = store.Update(&verifier.ProfileUpdate{ID: id, Name: "updated profile", Checks: checks})
		require.NoError(t, err)

		profileUpdated, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profileUpdated)
		require.Equal(t, "updated profile", profileUpdated.Name)
		require.Equal(t, "https://verifer.example.com", profileUpdated.URL)
		require.Equal(t, true, profileUpdated.Active)
		require.EqualValues(t, checks, profileUpdated.Checks)
		require.Equal(t, nil, profileUpdated.OIDCConfig)
		require.Equal(t, "org1", profileUpdated.OrganizationID)
	})

	t.Run("Activate/Deactivate profile", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{Name: "Test1", Active: true})
		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.True(t, profile.Active)
		require.Equal(t, id, profile.ID)

		err = store.UpdateActiveField(profile.ID, false)
		require.NoError(t, err)

		deactivated, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, deactivated)
		require.False(t, deactivated.Active)

		err = store.UpdateActiveField(profile.ID, true)
		require.NoError(t, err)

		activated, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, activated)
		require.True(t, activated.Active)
	})

	t.Run("Delete profile", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{Name: "Test1"})
		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.Equal(t, id, profile.ID)

		err = store.Delete(profile.ID)
		require.NoError(t, err)

		_, err = store.Find(id)
		require.EqualError(t, err, verifier.ErrProfileNotFound.Error())
	})
}

func TestProfileStore_Fails(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := verifierstore.NewProfileStore(client)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create invalid profile id", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{ID: "invalid"})
		require.Contains(t, err.Error(), "verifier profile invalid id")
		require.Empty(t, id)
	})

	t.Run("Create profile same id", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{})
		require.NoError(t, err)
		require.NotEmpty(t, id)

		id2, err := store.Create(&verifier.Profile{ID: id})
		require.Contains(t, err.Error(), "duplicate key error collection")
		require.Empty(t, id2)
	})

	t.Run("Update invalid profile id", func(t *testing.T) {
		err := store.Update(&verifier.ProfileUpdate{ID: "invalid"})
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Update not existing profile id", func(t *testing.T) {
		err := store.Update(&verifier.ProfileUpdate{ID: "121212121212121212121212", Name: "Test"})
		require.Contains(t, err.Error(), "profile with given id not found")
	})

	t.Run("Find invalid profile id", func(t *testing.T) {
		_, err := store.Find("invalid")
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Find not existing profile id", func(t *testing.T) {
		_, err := store.Find("121212121212121212121212")
		require.EqualError(t, err, verifier.ErrProfileNotFound.Error())
	})

	t.Run("Activate invalid profile id", func(t *testing.T) {
		err := store.UpdateActiveField("invalid", true)
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Activate not existing profile id", func(t *testing.T) {
		err := store.UpdateActiveField("121212121212121212121212", true)
		require.Contains(t, err.Error(), "profile with given id not found")
	})

	t.Run("Delete invalid profile id", func(t *testing.T) {
		err := store.Delete("invalid")
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Delete not existing profile id", func(t *testing.T) {
		err := store.Delete("121212121212121212121212")
		require.Contains(t, err.Error(), "profile with given id not found")
	})
}

func startMongoDBContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27018"}},
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
