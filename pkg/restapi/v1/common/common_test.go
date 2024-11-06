/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"errors"
	"testing"

	"github.com/jinzhu/copier"
	"github.com/stretchr/testify/require"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
)

func TestController_MapToKMSConfigType(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpe, err := MapToKMSConfigType(vcskms.AWS)
		require.NoError(t, err)
		require.Equal(t, KMSConfigTypeAws, tpe)

		tpe, err = MapToKMSConfigType(vcskms.Local)
		require.NoError(t, err)
		require.Equal(t, KMSConfigTypeLocal, tpe)

		tpe, err = MapToKMSConfigType(vcskms.Web)
		require.NoError(t, err)
		require.Equal(t, KMSConfigTypeWeb, tpe)
	})

	t.Run("Failed", func(t *testing.T) {
		_, err := MapToKMSConfigType("incorrect")
		require.Error(t, err)
	})
}

func TestController_ValidateKMSConfig(t *testing.T) {
	t.Run("Success (use default config)", func(t *testing.T) {
		res, err := ValidateKMSConfig(nil)
		require.NoError(t, err)
		require.Nil(t, res)
	})

	t.Run("Success(type aws)", func(t *testing.T) {
		config := &KMSConfig{
			Endpoint: strPtr("aws://url"),
			Type:     "aws",
		}

		_, err := ValidateKMSConfig(config)
		require.NoError(t, err)
	})

	t.Run("Missed endpoint (type aws)", func(t *testing.T) {
		config := &KMSConfig{
			Type: "aws",
		}

		_, err := ValidateKMSConfig(config)
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.endpoint", err)
	})

	t.Run("Success(type web)", func(t *testing.T) {
		config := &KMSConfig{
			Endpoint: strPtr("aws://url"),
			Type:     "web",
		}

		_, err := ValidateKMSConfig(config)
		require.NoError(t, err)
	})

	t.Run("Missed endpoint (type web)", func(t *testing.T) {
		config := &KMSConfig{
			Type: "web",
		}

		_, err := ValidateKMSConfig(config)
		requireValidationError(t, resterr.InvalidValue, "kmsConfig.endpoint", err)
	})

	t.Run("Success(type local)", func(t *testing.T) {
		config := &KMSConfig{
			DbPrefix:          strPtr("prefix"),
			DbType:            strPtr("type"),
			DbURL:             strPtr("url"),
			SecretLockKeyPath: strPtr("path"),
			Type:              "local",
		}

		_, err := ValidateKMSConfig(config)
		require.NoError(t, err)
	})

	t.Run("Missed fields (type local)", func(t *testing.T) {
		correct := &KMSConfig{
			DbPrefix:          strPtr("prefix"),
			DbType:            strPtr("type"),
			DbURL:             strPtr("url"),
			SecretLockKeyPath: strPtr("path"),
			Type:              "local",
		}

		incorrect := &KMSConfig{}

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.DbPrefix = nil
		_, err := ValidateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.dbPrefix", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.Type = "incorrect"
		_, err = ValidateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.type", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.DbURL = nil
		_, err = ValidateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.dbURL", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.DbType = nil
		_, err = ValidateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.dbType", err)

		require.NoError(t, copier.Copy(incorrect, correct))
		incorrect.SecretLockKeyPath = nil
		_, err = ValidateKMSConfig(incorrect)

		requireValidationError(t, resterr.InvalidValue, "kmsConfig.secretLockKeyPath", err)
	})
}

func TestController_mapToVPFormat(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpe, err := MapToVPFormat(vcsverifiable.Jwt)
		require.NoError(t, err)
		require.Equal(t, JwtVp, tpe)

		tpe, err = MapToVPFormat(vcsverifiable.Ldp)
		require.NoError(t, err)
		require.Equal(t, LdpVp, tpe)

		tpe, err = MapToVPFormat(vcsverifiable.Cwt)
		require.NoError(t, err)
		require.Equal(t, CwtVp, tpe)
	})

	t.Run("Failed", func(t *testing.T) {
		_, err := MapToVPFormat("incorrect")
		require.Error(t, err)
	})
}

func TestController_mapToDIDMethod(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpe, err := MapToDIDMethod(profileapi.KeyDIDMethod)
		require.NoError(t, err)
		require.Equal(t, DIDMethodKey, tpe)

		tpe, err = MapToDIDMethod(profileapi.OrbDIDMethod)
		require.NoError(t, err)
		require.Equal(t, DIDMethodOrb, tpe)

		tpe, err = MapToDIDMethod(profileapi.WebDIDMethod)
		require.NoError(t, err)
		require.Equal(t, DIDMethodWeb, tpe)
	})

	t.Run("Failed", func(t *testing.T) {
		_, err := MapToDIDMethod("incorrect")
		require.Error(t, err)
	})
}

func TestValidateVCFormat(t *testing.T) {
	got, err := ValidateVCFormat(JwtVcJsonLd)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Jwt, got)

	got, err = ValidateVCFormat(LdpVc)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Ldp, got)

	got, err = ValidateVCFormat(JwtVcJson)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Jwt, got)

	got, err = ValidateVCFormat(CwtVcLd)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Cwt, got)

	_, err = ValidateVCFormat("invalid")
	require.Error(t, err)
}

func TestValidateVPFormat(t *testing.T) {
	got, err := ValidateVPFormat(JwtVp)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Jwt, got)

	got, err = ValidateVPFormat(LdpVp)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Ldp, got)

	got, err = ValidateVPFormat(CwtVp)
	require.NoError(t, err)
	require.Equal(t, vcsverifiable.Cwt, got)

	_, err = ValidateVPFormat("invalid")
	require.Error(t, err)
}

func TestMapVcFormat(t *testing.T) {
	got, err := MapToVCFormat(vcsverifiable.Jwt)
	require.NoError(t, err)
	require.EqualValues(t, JwtVcJson, got)

	got, err = MapToVCFormat(vcsverifiable.Ldp)
	require.NoError(t, err)
	require.EqualValues(t, JwtVcJsonLd, got)

	got, err = MapToVCFormat(vcsverifiable.Cwt)
	require.NoError(t, err)
	require.EqualValues(t, CwtVcLd, got)

	_, err = MapToVCFormat("invalid")
	require.Error(t, err)
}

func TestValidateDIDMethod(t *testing.T) {
	got, err := ValidateDIDMethod(DIDMethodKey)
	require.NoError(t, err)
	require.Equal(t, profileapi.KeyDIDMethod, got)

	got, err = ValidateDIDMethod(DIDMethodWeb)
	require.NoError(t, err)
	require.Equal(t, profileapi.WebDIDMethod, got)

	got, err = ValidateDIDMethod(DIDMethodOrb)
	require.NoError(t, err)
	require.Equal(t, profileapi.OrbDIDMethod, got)

	_, err = ValidateDIDMethod("invalid")
	require.Error(t, err)
}

func strPtr(str string) *string {
	return &str
}

// nolint: unparam
func requireValidationError(t *testing.T, expectedCode resterr.ErrorCode, incorrectValueName string, actual error) {
	require.IsType(t, &resterr.CustomError{}, actual)
	actualErr := &resterr.CustomError{}
	require.True(t, errors.As(actual, &actualErr))

	require.Equal(t, expectedCode, actualErr.Code)
	require.Equal(t, incorrectValueName, actualErr.IncorrectValue)
	require.Error(t, actualErr.Err)
}
