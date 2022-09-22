/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"

	didcreator "github.com/trustbloc/vcs/pkg/did"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/issuer"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/kms/mocks"
)

func TestProfileService_Create(t *testing.T) {
	kmsRegistry := NewMockKMSRegistry(gomock.NewController(t))
	keyManager := mocks.NewMockVCSKeyManager(gomock.NewController(t))

	kmsRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(keyManager, nil)

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		didCreator := NewMockDIDCreator(ctrl)

		store.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return("id", nil)
		store.EXPECT().Find("id").Times(1).Return(&issuer.Profile{ID: "id"}, nil)

		didCreator.EXPECT().PublicDID(didcreator.OrbDIDMethod, vc.Ed25519Signature2018, arieskms.ED25519Type,
			gomock.Any()).Times(1).
			Return(&didcreator.CreateResult{
				DocResolution: &did.DocResolution{
					DIDDocument: &did.Doc{
						ID: fmt.Sprintf("did:example:%s", uuid.New().String()),
					},
				},
			}, nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
			DIDCreator:   didCreator,
			KMSRegistry:  kmsRegistry,
		})

		profile, err := service.Create(&issuer.Profile{
			VCConfig: &issuer.VCConfig{Format: "ldp_vc", SigningAlgorithm: vc.Ed25519Signature2018,
				DIDMethod: didcreator.OrbDIDMethod,
				KeyType:   arieskms.ED25519Type},
		}, []*cm.CredentialManifest{})

		require.NoError(t, err)
		require.Equal(t, "id", profile.ID)
	})

	t.Run("Create Fail", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		didCreator := NewMockDIDCreator(ctrl)

		store.EXPECT().Create(gomock.Any(), gomock.Any()).
			Times(1).Return("", errors.New("create failed"))
		didCreator.EXPECT().PublicDID(didcreator.OrbDIDMethod, vc.Ed25519Signature2018, arieskms.ED25519Type,
			gomock.Any()).Times(1).
			Return(&didcreator.CreateResult{
				DocResolution: &did.DocResolution{
					DIDDocument: &did.Doc{
						ID: fmt.Sprintf("did:example:%s", uuid.New().String()),
					},
				},
			}, nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
			DIDCreator:   didCreator,
			KMSRegistry:  kmsRegistry,
		})

		_, err := service.Create(&issuer.Profile{
			VCConfig: &issuer.VCConfig{Format: "ldp_vc", SigningAlgorithm: vc.Ed25519Signature2018,
				DIDMethod: didcreator.OrbDIDMethod, KeyType: arieskms.ED25519Type},
		}, []*cm.CredentialManifest{})
		require.Error(t, err)
	})

	t.Run("Create Fail 2", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		didCreator := NewMockDIDCreator(ctrl)

		store.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).Return("id", nil)
		store.EXPECT().Find("id").Times(1).Return(nil, errors.New("create failed"))
		didCreator.EXPECT().PublicDID(didcreator.OrbDIDMethod, vc.Ed25519Signature2018, arieskms.ED25519Type,
			gomock.Any()).Times(1).
			Return(&didcreator.CreateResult{
				DocResolution: &did.DocResolution{
					DIDDocument: &did.Doc{
						ID: fmt.Sprintf("did:example:%s", uuid.New().String()),
					},
				},
			}, nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
			DIDCreator:   didCreator,
			KMSRegistry:  kmsRegistry,
		})

		_, err := service.Create(&issuer.Profile{
			VCConfig: &issuer.VCConfig{Format: "ldp_vc", SigningAlgorithm: vc.Ed25519Signature2018,
				DIDMethod: didcreator.OrbDIDMethod, KeyType: arieskms.ED25519Type},
		}, []*cm.CredentialManifest{})
		require.Error(t, err)
	})

	t.Run("Create Fail kms registry error", func(t *testing.T) {
		brokenKMSRegistry := NewMockKMSRegistry(gomock.NewController(t))

		brokenKMSRegistry.EXPECT().GetKeyManager(gomock.Any()).AnyTimes().Return(nil,
			errors.New("fail to create key manager"))

		ctrl := gomock.NewController(t)

		store := NewMockProfileStore(ctrl)
		didCreator := NewMockDIDCreator(ctrl)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
			DIDCreator:   didCreator,
			KMSRegistry:  brokenKMSRegistry,
		})

		_, err := service.Create(&issuer.Profile{
			VCConfig: &issuer.VCConfig{
				Format:           "ldp_vc",
				SigningAlgorithm: vc.Ed25519Signature2018,
				DIDMethod:        didcreator.OrbDIDMethod,
			},
		}, []*cm.CredentialManifest{})
		require.Error(t, err)
	})

	t.Run("Create Fail did create failed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		didCreator := NewMockDIDCreator(ctrl)
		didCreator.EXPECT().PublicDID(didcreator.OrbDIDMethod, vc.Ed25519Signature2018, arieskms.ED25519Type,
			gomock.Any()).Times(1).Return(nil, errors.New("create did failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
			DIDCreator:   didCreator,
			KMSRegistry:  kmsRegistry,
		})

		_, err := service.Create(&issuer.Profile{
			VCConfig: &issuer.VCConfig{
				Format:           "ldp_vc",
				SigningAlgorithm: vc.Ed25519Signature2018,
				DIDMethod:        didcreator.OrbDIDMethod,
				KeyType:          arieskms.ED25519Type,
			},
		}, []*cm.CredentialManifest{})
		require.Error(t, err)
	})
}

func TestProfileService_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Update(&issuer.ProfileUpdate{ID: "id", Name: "test"}).Times(1).Return(nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		err := service.Update(&issuer.ProfileUpdate{ID: "id", Name: "test"})
		require.NoError(t, err)
	})

	t.Run("Update Fail", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Update(&issuer.ProfileUpdate{ID: "id", Name: "test"}).Times(1).Return(errors.New("update failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		err := service.Update(&issuer.ProfileUpdate{ID: "id", Name: "test"})
		require.Error(t, err)
	})
}

func TestProfileService_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Delete("id").Times(1).Return(nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		err := service.Delete("id")

		require.NoError(t, err)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Delete("id").Times(1).Return(errors.New("delete failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

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

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		err := service.ActivateProfile("id")

		require.NoError(t, err)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().UpdateActiveField("id", true).Times(1).Return(errors.New("failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

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

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		err := service.DeactivateProfile("id")

		require.NoError(t, err)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().UpdateActiveField("id", false).Times(1).Return(errors.New("failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		err := service.DeactivateProfile("id")

		require.Error(t, err)
	})
}

func TestProfileService_Find(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		store.EXPECT().Find("id").Times(1).Return(&issuer.Profile{ID: "id"}, nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		profile, err := service.GetProfile("id")

		require.NoError(t, err)
		require.Equal(t, "id", profile.ID)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().Find("id").Times(1).Return(nil, errors.New("failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		_, err := service.GetProfile("id")
		require.Error(t, err)
	})
}

func TestProfileService_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)
		store.EXPECT().FindByOrgID("orgID").Times(1).Return([]*issuer.Profile{{ID: "id"}}, nil)

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		profiles, err := service.GetAllProfiles("orgID")

		require.NoError(t, err)
		require.Len(t, profiles, 1)
	})

	t.Run("Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := NewMockProfileStore(ctrl)

		store.EXPECT().FindByOrgID("orgID").Times(1).Return(nil, errors.New("failed"))

		service := issuer.NewProfileService(&issuer.ServiceConfig{
			ProfileStore: store,
		})

		_, err := service.GetAllProfiles("orgID")

		require.Error(t, err)
	})
}

type mockKeyCreator struct {
}

func (c *mockKeyCreator) CreateJWKKey(keyType arieskms.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}
func (c *mockKeyCreator) CreateCryptoKey(keyType arieskms.KeyType) (string, interface{}, error) {
	return "", nil, nil
}

func KeysCreatorSuccess(config *kms.Config) (didcreator.KeysCreator, error) {
	return &mockKeyCreator{}, nil
}

func KeysCreatorFailed(config *kms.Config) (didcreator.KeysCreator, error) {
	return nil, errors.New("fail to create key creator")
}
