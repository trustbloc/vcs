/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuerstore_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/issuer"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/issuerstore"
)

const (
	mongoDBConnString  = "mongodb://localhost:27019"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

func TestProfileStore_Success(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := issuerstore.NewProfileStore(client)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create profile", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create profile with default kms config", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			VCConfig:   &issuer.VCConfig{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.NoError(t, err)
		require.NotNil(t, id)
	})

	t.Run("Create profile then find by id", func(t *testing.T) {
		expected := &issuer.Profile{
			VCConfig:  &issuer.VCConfig{},
			KMSConfig: &kms.Config{},
		}

		expectedCM := &cm.CredentialManifest{
			ID: "test-id",
		}

		id, err := store.Create(expected, []*cm.CredentialManifest{expectedCM})

		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
	})

	t.Run("Create profile with default kms config and then get", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			VCConfig:   &issuer.VCConfig{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
	})

	t.Run("Create profile then find by id", func(t *testing.T) {
		_, err := store.Create(&issuer.Profile{
			OrganizationID: "test1",
			VCConfig:       &issuer.VCConfig{},
			KMSConfig:      &kms.Config{},
			SigningDID:     &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.NoError(t, err)

		_, err = store.Create(&issuer.Profile{
			OrganizationID: "test1",
			VCConfig:       &issuer.VCConfig{},
			KMSConfig:      &kms.Config{},
			SigningDID:     &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.NoError(t, err)

		_, err = store.Create(&issuer.Profile{
			OrganizationID: "test2",
			VCConfig:       &issuer.VCConfig{},
			KMSConfig:      &kms.Config{},
			SigningDID:     &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.NoError(t, err)

		profiles, err := store.FindByOrgID("test1")
		require.NoError(t, err)
		require.Len(t, profiles, 2)
	})

	t.Run("Update profile", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			Name:       "Test1",
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})

		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.Equal(t, "Test1", profile.Name)
		require.Equal(t, id, profile.ID)

		err = store.Update(&issuer.ProfileUpdate{ID: id, Name: "Test2"})
		require.NoError(t, err)

		profileUpdated, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profileUpdated)
		require.Equal(t, "Test2", profileUpdated.Name)
	})

	t.Run("Activate/Deactivate profile", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			Name:       "Test1",
			Active:     true,
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
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
		id, err := store.Create(&issuer.Profile{
			Name:       "Test1",
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})

		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.Equal(t, id, profile.ID)

		err = store.Delete(profile.ID)
		require.NoError(t, err)

		_, err = store.Find(id)
		require.EqualError(t, err, issuer.ErrDataNotFound.Error())
	})

	t.Run("Delete profile with out credential manifests", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			Name:       "Test1",
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, nil)

		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.Equal(t, id, profile.ID)

		err = store.Delete(profile.ID)
		require.NoError(t, err)

		_, err = store.Find(id)
		require.EqualError(t, err, issuer.ErrDataNotFound.Error())
	})

	t.Run("Find credential manifest", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			Name:       "Test1",
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		},
			[]*cm.CredentialManifest{{ID: "testID",
				OutputDescriptors: []*cm.OutputDescriptor{{
					ID:     "Test",
					Schema: "Schema",
				}},
				Issuer: cm.Issuer{
					ID: "Test",
				}},
			})

		require.NoError(t, err)
		require.NotNil(t, id)

		manifests, err := store.FindCredentialManifests(id)
		require.NoError(t, err)
		require.Len(t, manifests, 1)
		require.Equal(t, "testID", manifests[0].ID)
	})
}

func TestProfileStore_Fails(t *testing.T) {
	pool, mongoDBResource := startMongoDBContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	client, err := mongodb.New(mongoDBConnString, "testdb", time.Second*10)
	require.NoError(t, err)

	store := issuerstore.NewProfileStore(client)
	require.NotNil(t, store)
	defer func() {
		require.NoError(t, client.Close(), "failed to close mongodb client")
	}()

	t.Run("Create invalid profile id", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			ID:         "invalid",
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.Contains(t, err.Error(), "issuer profile invalid id")
		require.Empty(t, id)
	})

	t.Run("Create profile same id", func(t *testing.T) {
		id, err := store.Create(&issuer.Profile{
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})

		require.NoError(t, err)
		require.NotEmpty(t, id)

		id2, err := store.Create(&issuer.Profile{
			ID:         id,
			VCConfig:   &issuer.VCConfig{},
			KMSConfig:  &kms.Config{},
			SigningDID: &issuer.SigningDID{},
		}, []*cm.CredentialManifest{{}})
		require.Contains(t, err.Error(), "duplicate key error collection")
		require.Empty(t, id2)
	})

	t.Run("Update invalid profile id", func(t *testing.T) {
		err := store.Update(&issuer.ProfileUpdate{ID: "invalid"})
		require.Contains(t, err.Error(), "issuer profile invalid id")
	})

	t.Run("Update not existing profile id", func(t *testing.T) {
		err := store.Update(&issuer.ProfileUpdate{ID: "121212121212121212121212", Name: "Test"})
		require.Contains(t, err.Error(), "profile with given id not found")
	})

	t.Run("Find invalid profile id", func(t *testing.T) {
		_, err := store.Find("invalid")
		require.Contains(t, err.Error(), "issuer profile invalid id")
	})

	t.Run("Find not existing profile id", func(t *testing.T) {
		_, err := store.Find("121212121212121212121212")
		require.EqualError(t, err, issuer.ErrDataNotFound.Error())
	})

	t.Run("Activate invalid profile id", func(t *testing.T) {
		err := store.UpdateActiveField("invalid", true)
		require.Contains(t, err.Error(), "issuer profile invalid id")
	})

	t.Run("Activate not existing profile id", func(t *testing.T) {
		err := store.UpdateActiveField("121212121212121212121212", true)
		require.Contains(t, err.Error(), "profile with given id not found")
	})

	t.Run("Delete invalid profile id", func(t *testing.T) {
		err := store.Delete("invalid")
		require.Contains(t, err.Error(), "issuer profile invalid id")
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
			"27017/tcp": {{HostIP: "", HostPort: "27019"}},
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
