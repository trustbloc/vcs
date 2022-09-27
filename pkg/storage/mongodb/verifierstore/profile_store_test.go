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
	"github.com/go-test/deep"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/verifierstore"
	"github.com/trustbloc/vcs/pkg/verifier"
)

const (
	mongoDBConnString  = "mongodb://localhost:27018"
	dockerMongoDBImage = "mongo"
	dockerMongoDBTag   = "4.0.0"
)

//nolint:gochecknoglobals
var checks = &verifier.VerificationChecks{
	Credential: verifier.CredentialChecks{
		Proof: true,
		Format: []vcsverifiable.Format{
			vcsverifiable.Jwt,
			vcsverifiable.Ldp,
		},
		Status: true,
	},
	Presentation: &verifier.PresentationChecks{
		Proof: true,
		Format: []vcsverifiable.Format{
			vcsverifiable.Jwt,
			vcsverifiable.Ldp,
		},
	},
}

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
		predicate := presexch.Required
		strFilterType := "string"

		pd := &presexch.PresentationDefinition{
			ID: uuid.New().String(),
			InputDescriptors: []*presexch.InputDescriptor{{
				ID: uuid.New().String(),
				Schema: []*presexch.Schema{{
					URI: fmt.Sprintf("%s#%s", verifiable.ContextID, verifiable.VCType),
				}},
				Constraints: &presexch.Constraints{
					Fields: []*presexch.Field{{
						Path:      []string{"$.first_name", "$.last_name"},
						Predicate: &predicate,
						Filter:    &presexch.Filter{Type: &strFilterType},
					}},
				},
			}},
		}

		require.NoError(t, pd.ValidateSchema())

		id, err := store.Create(&verifier.Profile{
			Name:   "test profile",
			URL:    "https://verifer.example.com",
			Active: true,
			Checks: checks,
			OIDCConfig: &verifier.OIDC4VPConfig{
				ROSigningAlgorithm: "Test1",
				DIDMethod:          "Test2",
				KeyType:            "Test3",
			},
			OrganizationID: "org1",
		}, []*presexch.PresentationDefinition{pd})
		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)

		presentationDefinition, err := store.FindPresentationDefinition(id, "")
		require.NoError(t, err)
		require.NotNil(t, presentationDefinition)

		require.NoError(t, presentationDefinition.ValidateSchema())

		if diff := deep.Equal(pd, presentationDefinition); diff != nil {
			t.Error(diff)
		}

		presentationDefinition, err = store.FindPresentationDefinition(id, pd.ID)
		require.NoError(t, err)
		require.NotNil(t, presentationDefinition)

		require.NoError(t, presentationDefinition.ValidateSchema())

		if diff := deep.Equal(pd, presentationDefinition); diff != nil {
			t.Error(diff)
		}
	})

	t.Run("Create profile then find by id", func(t *testing.T) {
		_, err := store.Create(&verifier.Profile{OrganizationID: "test1", Checks: checks}, nil)
		require.NoError(t, err)

		_, err = store.Create(&verifier.Profile{OrganizationID: "test1", Checks: checks}, nil)
		require.NoError(t, err)

		_, err = store.Create(&verifier.Profile{OrganizationID: "test2", Checks: checks}, nil)
		require.NoError(t, err)

		profiles, err := store.FindByOrgID("test1")
		require.NoError(t, err)
		require.Len(t, profiles, 2)
	})

	t.Run("Update profile", func(t *testing.T) {
		uchecks := &verifier.VerificationChecks{
			Credential: verifier.CredentialChecks{
				Proof: true,
				Format: []vcsverifiable.Format{
					vcsverifiable.Jwt,
					vcsverifiable.Ldp,
				},
				Status: true,
			},
			Presentation: &verifier.PresentationChecks{
				Proof: true,
				Format: []vcsverifiable.Format{
					vcsverifiable.Jwt,
					vcsverifiable.Ldp,
				},
			},
		}

		id, err := store.Create(&verifier.Profile{
			Name:           "test profile",
			URL:            "https://verifer.example.com",
			Active:         true,
			Checks:         uchecks,
			OIDCConfig:     nil,
			OrganizationID: "org1",
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, id)

		profile, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.Equal(t, "test profile", profile.Name)
		require.Equal(t, id, profile.ID)

		uchecks.Credential.Format = []vcsverifiable.Format{vcsverifiable.Ldp}
		uchecks.Presentation.Format = []vcsverifiable.Format{vcsverifiable.Ldp}

		err = store.Update(&verifier.ProfileUpdate{ID: id, Name: "updated profile", Checks: uchecks})
		require.NoError(t, err)

		profileUpdated, err := store.Find(id)
		require.NoError(t, err)
		require.NotNil(t, profileUpdated)
		require.Equal(t, "updated profile", profileUpdated.Name)
		require.Equal(t, "https://verifer.example.com", profileUpdated.URL)
		require.Equal(t, true, profileUpdated.Active)
		require.EqualValues(t, uchecks, profileUpdated.Checks)
		require.Equal(t, "org1", profileUpdated.OrganizationID)
	})

	t.Run("Activate/Deactivate profile", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{Name: "Test1", Active: true, Checks: checks}, nil)
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
		id, err := store.Create(&verifier.Profile{Name: "Test1", Checks: checks}, nil)
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
		id, err := store.Create(&verifier.Profile{ID: "invalid"}, nil)
		require.Contains(t, err.Error(), "verifier profile invalid id")
		require.Empty(t, id)
	})

	t.Run("Create profile same id", func(t *testing.T) {
		id, err := store.Create(&verifier.Profile{Checks: checks}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		id2, err := store.Create(&verifier.Profile{ID: id, Checks: checks}, nil)
		require.Contains(t, err.Error(), "duplicate key error collection")
		require.Empty(t, id2)
	})

	t.Run("Update invalid profile id", func(t *testing.T) {
		err := store.Update(&verifier.ProfileUpdate{ID: "invalid"})
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Update not existing profile id", func(t *testing.T) {
		err := store.Update(&verifier.ProfileUpdate{ID: "121212121212121212121212", Name: "Test", Checks: checks})
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

	t.Run("Find invalid profile id", func(t *testing.T) {
		_, err := store.Find("invalid")
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Find presentation definition with invalid profile id", func(t *testing.T) {
		_, err := store.FindPresentationDefinition("invalid", "")
		require.Contains(t, err.Error(), "verifier profile invalid id")
	})

	t.Run("Find not existing presentation definition ", func(t *testing.T) {
		_, err := store.FindPresentationDefinition("121212121212121212121212", "")
		require.EqualError(t, err, verifier.ErrProfileNotFound.Error())
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
