/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesprovider

import (
	"encoding/json"
	"strconv"

	"github.com/trustbloc/vcs/pkg/storage"

	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	cslStoreName           = "credentialstatus"
	latestListIDDBEntryKey = "LatestListID"
)

type AriesCSLStore struct {
	ariesStore ariesstorage.Store
}

func (a *AriesVCSProvider) OpenCSLStore() (storage.CSLStore, error) {
	ariesStore, err := a.provider.OpenStore(cslStoreName)
	if err != nil {
		return nil, err
	}

	return &AriesCSLStore{ariesStore: ariesStore}, nil
}

func (c *AriesCSLStore) PutCSLWrapper(cslWrapper *storage.CSLWrapper) error {
	cslWrapperBytes, err := json.Marshal(cslWrapper)
	if err != nil {
		return err
	}

	return c.ariesStore.Put(cslWrapper.VC.ID, cslWrapperBytes)
}

func (c *AriesCSLStore) GetCSLWrapper(id string) (*storage.CSLWrapper, error) {
	cslWrapperBytes, err := c.ariesStore.Get(id)
	if err != nil {
		return nil, err
	}

	var cslWrapper storage.CSLWrapper

	err = json.Unmarshal(cslWrapperBytes, &cslWrapper)
	if err != nil {
		return nil, err
	}

	return &cslWrapper, nil
}

func (c *AriesCSLStore) UpdateLatestListID(id int) error {
	idAsString := strconv.Itoa(id)

	return c.ariesStore.Put(latestListIDDBEntryKey, []byte(idAsString))
}

func (c *AriesCSLStore) GetLatestListID() (int, error) {
	latestListIDBytes, err := c.ariesStore.Get(latestListIDDBEntryKey)
	if err != nil {
		return -1, err
	}

	latestListID, err := strconv.Atoi(string(latestListIDBytes))
	if err != nil {
		return -1, err
	}

	return latestListID, nil
}
