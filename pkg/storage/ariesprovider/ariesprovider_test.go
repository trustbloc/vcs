/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesprovider_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/trustbloc/vcs/pkg/storage/ariesprovider"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	ariesspi "github.com/hyperledger/aries-framework-go/spi/storage"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	vcsstorage "github.com/trustbloc/vcs/pkg/storage"
)

func TestCommonSuccessCases(t *testing.T) {
	provider := ariesmemstorage.NewProvider()

	storageProvider := ariesprovider.New(provider)

	t.Run("Get Aries storage provider", func(t *testing.T) {
		returnedAriesProvider := storageProvider.GetAriesProvider()
		require.Equal(t, provider, returnedAriesProvider)
	})
	t.Run("Using master key store", func(t *testing.T) {
		masterKeyStore, err := storageProvider.OpenMasterKeyStore()
		require.NoError(t, err)

		testBytes := []byte{0, 1, 1, 2, 3, 5, 8, 13, 21, 34}

		err = masterKeyStore.Put(testBytes)
		require.NoError(t, err)

		retrievedBytes, err := masterKeyStore.Get()
		require.NoError(t, err)
		require.Equal(t, testBytes, retrievedBytes)
	})
	t.Run("Using VC store", func(t *testing.T) {
		vcStore, err := storageProvider.OpenVCStore()
		require.NoError(t, err)

		const testVCID = "TestVCID"

		vc := &verifiable.Credential{ID: testVCID}

		const testProfileName = "TestProfileName"

		err = vcStore.Put(testProfileName, vc)
		require.NoError(t, err)

		vcBytes, err := vcStore.Get(testProfileName, testVCID)
		require.NoError(t, err)

		// Unmarshal into a map instead of using verifiable.ParseCredential since that
		// requires a lot of extra steps and dependencies.
		var vcAsMap map[string]interface{}

		err = json.Unmarshal(vcBytes, &vcAsMap)
		require.NoError(t, err)

		require.Equal(t, testVCID, vcAsMap["id"])
	})
	t.Run("Using CSL store", func(t *testing.T) {
		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		const testVCID = "TestVCID"

		vc := &verifiable.Credential{ID: testVCID}

		vcBytes, err := json.Marshal(vc)
		require.NoError(t, err)

		testCSLWrapper := vcsstorage.CSLWrapper{VCByte: vcBytes, ListID: 1, VC: vc}

		err = cslStore.PutCSLWrapper(&testCSLWrapper)
		require.NoError(t, err)

		retrievedCSLWrapper, err := cslStore.GetCSLWrapper(vc.ID)
		require.NoError(t, err)

		require.Equal(t, string(vcBytes), string(retrievedCSLWrapper.VCByte))

		latestListID := 1

		err = cslStore.UpdateLatestListID(latestListID)
		require.NoError(t, err)

		retrievedLatestListID, err := cslStore.GetLatestListID()
		require.NoError(t, err)
		require.Equal(t, latestListID, retrievedLatestListID)

		latestListID++

		err = cslStore.UpdateLatestListID(latestListID)
		require.NoError(t, err)

		retrievedLatestListID, err = cslStore.GetLatestListID()
		require.NoError(t, err)
		require.Equal(t, latestListID, retrievedLatestListID)
	})
	t.Run("Using holder profile store", func(t *testing.T) {
		holderProfileStore, err := storageProvider.OpenHolderProfileStore()
		require.NoError(t, err)

		testName := "TestName"

		holderProfile := vcsstorage.HolderProfile{
			DataProfile: vcsstorage.DataProfile{Name: testName},
		}

		err = holderProfileStore.Put(holderProfile)
		require.NoError(t, err)

		retrievedHolderProfile, err := holderProfileStore.Get(testName)
		require.NoError(t, err)
		require.Equal(t, holderProfile.Name, retrievedHolderProfile.Name)

		err = holderProfileStore.Delete(testName)
		require.NoError(t, err)

		retrievedHolderProfile, err = holderProfileStore.Get(testName)
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Empty(t, retrievedHolderProfile)
	})
	t.Run("Using issuer profile store", func(t *testing.T) {
		issuerProfileStore, err := storageProvider.OpenIssuerProfileStore()
		require.NoError(t, err)

		testName := "TestName"

		issuerProfile := vcsstorage.IssuerProfile{
			DataProfile: vcsstorage.DataProfile{Name: testName},
		}

		err = issuerProfileStore.Put(issuerProfile)
		require.NoError(t, err)

		retrievedIssuerProfile, err := issuerProfileStore.Get(testName)
		require.NoError(t, err)
		require.Equal(t, issuerProfile.Name, retrievedIssuerProfile.Name)

		err = issuerProfileStore.Delete(testName)
		require.NoError(t, err)

		retrievedIssuerProfile, err = issuerProfileStore.Get(testName)
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Empty(t, retrievedIssuerProfile)
	})
	t.Run("Using verifier profile store", func(t *testing.T) {
		verifierProfileStore, err := storageProvider.OpenVerifierProfileStore()
		require.NoError(t, err)

		testID := "TestID"

		verifierProfile := vcsstorage.VerifierProfile{
			ID: testID,
		}

		err = verifierProfileStore.Put(verifierProfile)
		require.NoError(t, err)

		retrievedVerifierProfile, err := verifierProfileStore.Get(testID)
		require.NoError(t, err)
		require.Equal(t, retrievedVerifierProfile.ID, retrievedVerifierProfile.ID)

		err = verifierProfileStore.Delete(testID)
		require.NoError(t, err)

		retrievedVerifierProfile, err = verifierProfileStore.Get(testID)
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Empty(t, retrievedVerifierProfile)
	})
}

func TestProvider_OpenMasterKeyStore(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("open store error"),
		})

		masterKeyStore, err := storageProvider.OpenMasterKeyStore()
		require.EqualError(t, err, "open store error")
		require.Nil(t, masterKeyStore)
	})
}

func TestProvider_VCStore(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("open store error"),
		})

		vcStore, err := storageProvider.OpenVCStore()
		require.EqualError(t, err, "open store error")
		require.Nil(t, vcStore)
	})
}

func TestProvider_CSLStore(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("open store error"),
		})

		cslStore, err := storageProvider.OpenCSLStore()
		require.EqualError(t, err, "open store error")
		require.Nil(t, cslStore)
	})
	t.Run("Fail to get CSL wrapper from underlying Aries store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{ErrGet: errors.New("get error")},
		})

		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		cslWrapper, err := cslStore.GetCSLWrapper("id")
		require.EqualError(t, err, "get error")
		require.Nil(t, cslWrapper)
	})
	t.Run("Fail to get CSL wrapper from underlying Aries store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{ErrGet: errors.New("get error")},
		})

		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		cslWrapper, err := cslStore.GetCSLWrapper("id")
		require.EqualError(t, err, "get error")
		require.Nil(t, cslWrapper)
	})
	t.Run("Fail to get latest list ID from underlying Aries store", func(t *testing.T) {
		storageProvider := ariesprovider.New(ariesmemstorage.NewProvider())

		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		latestListID, err := cslStore.GetLatestListID()
		require.Equal(t, ariesspi.ErrDataNotFound, err)
		require.Equal(t, -1, latestListID)
	})
	t.Run("Latest list ID is not a valid integer", func(t *testing.T) {
		underlyingMemProvider := ariesmemstorage.NewProvider()

		memStore, err := underlyingMemProvider.OpenStore("credentialstatus")
		require.NoError(t, err)

		err = memStore.Put("LatestListID", []byte("NotAnInteger"))
		require.NoError(t, err)

		storageProvider := ariesprovider.New(underlyingMemProvider)

		cslStore, err := storageProvider.OpenCSLStore()
		require.NoError(t, err)

		latestListID, err := cslStore.GetLatestListID()
		require.EqualError(t, err, `strconv.Atoi: parsing "NotAnInteger": invalid syntax`)
		require.Equal(t, -1, latestListID)
	})
}

func TestProvider_HolderProfileStore(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("open store error"),
		})

		holderProfileStore, err := storageProvider.OpenHolderProfileStore()
		require.EqualError(t, err, "open store error")
		require.Nil(t, holderProfileStore)
	})
}

func TestProvider_IssuerProfileStore(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("open store error"),
		})

		issuerProfileStore, err := storageProvider.OpenIssuerProfileStore()
		require.EqualError(t, err, "open store error")
		require.Nil(t, issuerProfileStore)
	})
}

func TestProvider_VerifierProfileStore(t *testing.T) {
	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := ariesprovider.New(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("open store error"),
		})

		verifierProfileStore, err := storageProvider.OpenVerifierProfileStore()
		require.EqualError(t, err, "open store error")
		require.Nil(t, verifierProfileStore)
	})
}
