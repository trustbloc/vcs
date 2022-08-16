/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/verifier"
)

func TestProfileService_Create(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Create(gomock.Any()).Times(1).Return("id", nil)
		store.EXPECT().Find("id").Times(1).Return(&verifier.Profile{ID: "id"}, nil)

		service := verifier.NewProfileService(store)

		profile, err := service.Create(&verifier.Profile{})

		require.NoError(t, err)
		require.Equal(t, "id", profile.ID)
	})

	t.Run("Create Fail", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Create(gomock.Any()).Times(1).Return("", errors.New("create failed"))

		service := verifier.NewProfileService(store)
		_, err := service.Create(&verifier.Profile{})
		require.Error(t, err)
	})

	t.Run("Create Fail 2", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Create(gomock.Any()).Times(1).Return("id", nil)
		store.EXPECT().Find("id").Times(1).Return(nil, errors.New("create failed"))

		service := verifier.NewProfileService(store)

		_, err := service.Create(&verifier.Profile{})
		require.Error(t, err)
	})
}

func TestProfileService_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Update(&verifier.ProfileUpdate{ID: "id", Name: "test"}).Times(1).Return(nil)
		store.EXPECT().Find("id").Times(1).Return(&verifier.Profile{ID: "id"}, nil)

		service := verifier.NewProfileService(store)

		profile, err := service.Update(&verifier.ProfileUpdate{ID: "id", Name: "test"})

		require.NoError(t, err)
		require.Equal(t, "id", profile.ID)
	})

	t.Run("Update Fail", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Update(&verifier.ProfileUpdate{ID: "id", Name: "test"}).Times(1).Return(errors.New("update failed"))

		service := verifier.NewProfileService(store)
		_, err := service.Update(&verifier.ProfileUpdate{ID: "id", Name: "test"})
		require.Error(t, err)
	})

	t.Run("Update Fail 2", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Update(&verifier.ProfileUpdate{ID: "id", Name: "test"}).Times(1).Return(nil)
		store.EXPECT().Find("id").Times(1).Return(nil, errors.New("create failed"))

		service := verifier.NewProfileService(store)

		_, err := service.Update(&verifier.ProfileUpdate{ID: "id", Name: "test"})
		require.Error(t, err)
	})
}

func TestProfileService_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Delete("id").Times(1).Return(nil)

		service := verifier.NewProfileService(store)

		err := service.Delete("id")

		require.NoError(t, err)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Delete("id").Times(1).Return(errors.New("delete failed"))

		service := verifier.NewProfileService(store)

		err := service.Delete("id")

		require.Error(t, err)
	})
}

func TestProfileService_ActivateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().UpdateActiveField("id", true).Times(1).Return(nil)

		service := verifier.NewProfileService(store)

		err := service.ActivateProfile("id")

		require.NoError(t, err)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().UpdateActiveField("id", true).Times(1).Return(errors.New("failed"))

		service := verifier.NewProfileService(store)

		err := service.ActivateProfile("id")

		require.Error(t, err)
	})
}

func TestProfileService_DeactivateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().UpdateActiveField("id", false).Times(1).Return(nil)

		service := verifier.NewProfileService(store)

		err := service.DeactivateProfile("id")

		require.NoError(t, err)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().UpdateActiveField("id", false).Times(1).Return(errors.New("failed"))

		service := verifier.NewProfileService(store)

		err := service.DeactivateProfile("id")

		require.Error(t, err)
	})
}

func TestProfileService_Find(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		store.EXPECT().Find("id").Times(1).Return(&verifier.Profile{ID: "id"}, nil)

		service := verifier.NewProfileService(store)

		profile, err := service.GetProfile("id")

		require.NoError(t, err)
		require.Equal(t, "id", profile.ID)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Find("id").Times(1).Return(nil, errors.New("failed"))

		service := verifier.NewProfileService(store)

		_, err := service.GetProfile("id")

		require.Error(t, err)
	})
}

func TestProfileService_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		store.EXPECT().FindByOrgID("orgID").Times(1).Return([]*verifier.Profile{{ID: "id"}}, nil)

		service := verifier.NewProfileService(store)

		profiles, err := service.GetAllProfiles("orgID")

		require.NoError(t, err)
		require.Len(t, profiles, 1)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().FindByOrgID("orgID").Times(1).Return(nil, errors.New("failed"))

		service := verifier.NewProfileService(store)

		_, err := service.GetAllProfiles("orgID")

		require.Error(t, err)
	})
}
