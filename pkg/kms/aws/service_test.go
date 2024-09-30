/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws //nolint:testpackage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	arieskms "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
)

func TestSign(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		testCases := []struct {
			name string
			sig  types.SigningAlgorithmSpec
			key  types.KeySpec
		}{
			{
				name: "P256",
				sig:  types.SigningAlgorithmSpecEcdsaSha256,
				key:  types.KeySpecEccNistP256,
			},
			{
				name: "P384",
				sig:  types.SigningAlgorithmSpecEcdsaSha384,
				key:  types.KeySpecEccNistP384,
			},
			{
				name: "P521",
				sig:  types.SigningAlgorithmSpecEcdsaSha512,
				key:  types.KeySpecEccNistP521,
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				metric := NewMockmetricsProvider(gomock.NewController(t))
				metric.EXPECT().SignCount()
				metric.EXPECT().SignTime(gomock.Any())

				client := NewMockawsClient(gomock.NewController(t))
				client.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&kms.SignOutput{
						Signature: []byte("data"),
					}, nil)

				client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&kms.DescribeKeyOutput{
						KeyMetadata: &types.KeyMetadata{
							SigningAlgorithms: []types.SigningAlgorithmSpec{testCase.sig},
							KeySpec:           testCase.key,
						},
					}, nil)

				suite := NewSuite(awsConfig, metric, "", WithAWSClient(client))

				suiteSigner, err := suite.KMSCryptoSigner()
				require.NoError(t, err)

				signature, err := suiteSigner.Sign([]byte("msg"), wrapKID(
					"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"))
				require.NoError(t, err)
				require.Contains(t, string(signature), "data")
			})
		}
	})

	t.Run("success p256k", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().SignCount()
		metric.EXPECT().SignTime(gomock.Any())

		sig := ecdsaSignature{
			R: big.NewInt(12345),
			S: big.NewInt(54321),
		}

		asnSig, err := asn1.Marshal(sig)
		require.NoError(t, err)

		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.SignOutput{
				Signature: asnSig,
			}, nil)

		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
					KeySpec:           types.KeySpecEccSecgP256k1,
				},
			}, nil)

		suite := NewSuite(awsConfig, metric, "", WithAWSClient(client))

		suiteSigner, err := suite.FixedKeySigner(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)

		signature, err := suiteSigner.Sign([]byte("msg"))
		require.NoError(t, err)
		require.Contains(t, string(signature), "\xd41")
	})

	t.Run("p256k asn error", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().SignCount()
		metric.EXPECT().SignTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.SignOutput{
				Signature: []byte("not an asn1 encoded signature"),
			}, nil)

		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
					KeySpec:           types.KeySpecEccSecgP256k1,
				},
			}, nil)

		suite := NewSuite(awsConfig, metric, "", WithAWSClient(client))

		suiteCrypto, err := suite.KMSCryptoSigner()
		require.NoError(t, err)

		suiteSigner, err := suiteCrypto.FixedKeySigner(wrapKID(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"))
		require.NoError(t, err)

		_, err = suiteSigner.Sign([]byte("msg"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "asn1:")
	})

	t.Run("failed to describe key", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().SignCount()
		metric.EXPECT().SignTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))

		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("failed to describe key"))

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		_, err := svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to describe key")
	})

	t.Run("unknown signing algorithm", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().SignCount()
		metric.EXPECT().SignTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))

		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					SigningAlgorithms: []types.SigningAlgorithmSpec{"not a signing alg"},
					KeySpec:           types.KeySpecEccNistP256,
				},
			}, nil)

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		_, err := svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown signing algorithm")
	})

	t.Run("failed to sign", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().SignCount()
		metric.EXPECT().SignTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().Sign(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("failed to sign"))
		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
				},
			}, nil)

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		_, err := svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().SignCount()
		metric.EXPECT().SignTime(gomock.Any())

		svc := New(awsConfig, metric, "", []Opts{}...)
		_, err := svc.Sign([]byte("msg"), "aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestHealthCheck(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.DescribeKeyOutput{}, nil)

		svc := New(awsConfig, metric,
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
			WithAWSClient(client),
		)

		err := svc.HealthCheck()
		require.NoError(t, err)
	})

	t.Run("invalid healthcheck key ID", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))

		svc := New(awsConfig, metric,
			"aws-kms://invalid",
			WithAWSClient(client),
		)

		err := svc.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})

	t.Run("failed to list keys", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().DescribeKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("failed to list keys"))

		svc := New(awsConfig, metric,
			"foo",
			WithAWSClient(client))

		err := svc.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to list keys")
	})
}

func TestCreate(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		keyID := "key1"

		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		result, _, err := svc.Create(arieskms.ECDSAP256DER)
		require.NoError(t, err)
		require.Contains(t, result, keyID)
	})

	t.Run("success RSA", func(t *testing.T) {
		keyID := "key1"

		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				input *kms.CreateKeyInput,
				f ...func(*kms.Options),
			) (*kms.CreateKeyOutput, error) {
				require.EqualValues(t, types.CustomerMasterKeySpecRsa2048, input.KeySpec)
				return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil
			})

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		result, _, err := svc.Create(arieskms.RSARS256)
		require.NoError(t, err)
		require.Contains(t, result, keyID)
	})

	t.Run("success: with key alias prefix", func(t *testing.T) {
		keyID := "key1"

		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)
		client.EXPECT().CreateAlias(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateAliasOutput{}, nil)

		svc := New(awsConfig, metric, "",
			WithKeyAliasPrefix("dummyKeyAlias"),
			WithAWSClient(client),
		)

		result, _, err := svc.Create(arieskms.ECDSAP384DER)
		require.NoError(t, err)
		require.Contains(t, result, keyID)
	})

	t.Run("key not supported", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))

		svc := New(awsConfig, metric, "", []Opts{}...)

		_, _, err := svc.Create(arieskms.ED25519)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported ED25519")
	})

	t.Run("create error", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("expected error"))

		svc := New(awsConfig, metric, "",
			WithKeyAliasPrefix("dummyKeyAlias"),
			WithAWSClient(client),
		)

		_, _, err := svc.Create(arieskms.ECDSASecp256k1DER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected error")
	})

	t.Run("key alias error", func(t *testing.T) {
		keyID := "key1"

		metric := NewMockmetricsProvider(gomock.NewController(t))
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)
		client.EXPECT().CreateAlias(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateAliasOutput{}, fmt.Errorf("expected error"))

		svc := New(awsConfig, metric, "",
			WithKeyAliasPrefix("dummyKeyAlias"),
			WithAWSClient(client),
		)

		_, _, err := svc.Create(arieskms.ECDSAP521DER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected error")
	})
}

func TestRemove(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		ctr := gomock.NewController(t)

		metric := NewMockmetricsProvider(ctr)
		client := NewMockawsClient(ctr)

		keyURI := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"
		expectedKeyID := "800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		client.EXPECT().ScheduleKeyDeletion(gomock.Any(), &kms.ScheduleKeyDeletionInput{KeyId: &expectedKeyID}).
			Return(nil, nil)

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		err := svc.Remove(keyURI)
		require.NoError(t, err)
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))

		svc := New(awsConfig, metric, "", []Opts{}...)

		err := svc.Remove("aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})

	t.Run("failed to schedule key deletion", func(t *testing.T) {
		ctr := gomock.NewController(t)

		metric := NewMockmetricsProvider(ctr)
		client := NewMockawsClient(ctr)

		keyURI := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"
		expectedKeyID := "800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		client.EXPECT().ScheduleKeyDeletion(gomock.Any(), &kms.ScheduleKeyDeletionInput{KeyId: &expectedKeyID}).
			Return(nil, errors.New("some error"))

		svc := New(awsConfig, metric, "", WithAWSClient(client))

		err := svc.Remove(keyURI)
		require.Error(t, err)
		require.Contains(t, err.Error(), "some error")
	})
}

func TestGet(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}
	metric := NewMockmetricsProvider(gomock.NewController(t))

	t.Run("success", func(t *testing.T) {
		svc := New(&awsConfig, metric, "", []Opts{}...)

		keyID, err := svc.Get("key1")
		require.NoError(t, err)
		require.Contains(t, keyID, "key1")
	})
}

func TestResolver(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}
	metric := NewMockmetricsProvider(gomock.NewController(t))

	t.Run("success", func(t *testing.T) {
		svc := New(&awsConfig, metric, "", []Opts{
			WithAWSEndpointResolverV2(&ExampleResolver{}),
		}...)

		keyID, err := svc.Get("key1")
		require.NoError(t, err)
		require.Contains(t, keyID, "key1")
	})
}

func TestCreateAndPubKeyBytes(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		keyID := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		mockPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockKeyBytes, err := x509.MarshalPKIXPublicKey(&mockPriv.PublicKey)
		require.NoError(t, err)

		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.GetPublicKeyOutput{
				PublicKey:         mockKeyBytes,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil)
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)

		suite := NewSuite(&awsConfig, metric, "", WithAWSClient(client))

		creator, err := suite.KeyCreator()
		require.NoError(t, err)

		pubKey, err := creator.Create(arieskms.ECDSAP256TypeDER)
		require.NoError(t, err)
		require.Equal(t, keyID, pubKey.KeyID)
		require.Equal(t, &mockPriv.PublicKey, pubKey.Key)
	})

	t.Run("success, raw key", func(t *testing.T) {
		keyID := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		mockPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockKeyBytes, err := x509.MarshalPKIXPublicKey(&mockPriv.PublicKey)
		require.NoError(t, err)

		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.GetPublicKeyOutput{
				PublicKey:         mockKeyBytes,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil)
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)

		suite := NewSuite(&awsConfig, metric, "", WithAWSClient(client))

		creator, err := suite.RawKeyCreator()
		require.NoError(t, err)

		gotKID, gotRaw, err := creator.CreateRaw(arieskms.ECDSAP256TypeDER)
		require.NoError(t, err)
		require.Equal(t, keyID, gotKID)
		require.Equal(t, &mockPriv.PublicKey, gotRaw)
	})

	t.Run("success, raw key ED25519", func(t *testing.T) {
		keyID := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		mockPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockKeyBytes, err := x509.MarshalPKIXPublicKey(&mockPriv.PublicKey)
		require.NoError(t, err)

		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.GetPublicKeyOutput{
				PublicKey:         mockKeyBytes,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil)
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)

		suite := NewSuite(&awsConfig, metric, "", WithAWSClient(client))

		creator, err := suite.RawKeyCreator()
		require.NoError(t, err)

		gotKID, gotRaw, err := creator.CreateRaw(arieskms.ED25519)
		require.NoError(t, err)
		require.Equal(t, keyID, gotKID)
		require.Equal(t, &mockPriv.PublicKey, gotRaw)
	})

	t.Run("key not supported", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))

		svc := New(&awsConfig, metric, "", []Opts{}...)

		_, _, err := svc.CreateAndExportPubKeyBytes(arieskms.ED25519)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported ED25519")

		suite := NewSuite(&awsConfig, metric, "", []Opts{}...)

		creator, err := suite.RawKeyCreator()
		require.NoError(t, err)

		_, err = creator.Create(arieskms.ED25519Type)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported ED25519")

		_, _, err = creator.CreateRaw(arieskms.ED25519Type)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported ED25519")
	})

	t.Run("export error", func(t *testing.T) {
		keyID := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil)
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("expected error"))

		svc := New(&awsConfig, metric, "", WithAWSClient(client))

		_, _, err := svc.CreateAndExportPubKeyBytes(arieskms.ECDSAP256DER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected error")
	})

	t.Run("service returns invalid key bytes", func(t *testing.T) {
		keyID := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		mockKeyBytes := []byte("invalid P256 DER key")

		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount().AnyTimes()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any()).AnyTimes()
		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.GetPublicKeyOutput{
				PublicKey:         mockKeyBytes,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil).AnyTimes()
		client.EXPECT().CreateKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil).AnyTimes()

		suite := NewSuite(&awsConfig, metric, "", WithAWSClient(client))

		creator, err := suite.RawKeyCreator()
		require.NoError(t, err)

		pubJWK, err := creator.Create(arieskms.ECDSAP256TypeDER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse ecdsa key")
		require.Nil(t, pubJWK)

		pubKID, pubRaw, err := creator.CreateRaw(arieskms.ECDSAP256TypeDER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse ecdsa key")
		require.Nil(t, pubRaw)
		require.Empty(t, pubKID)
	})
}

func TestSignMulti(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}
	metric := NewMockmetricsProvider(gomock.NewController(t))

	svc := New(&awsConfig, metric, "", []Opts{}...)

	_, err := svc.SignMulti(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")

	suite := NewSuite(&awsConfig, nil, "")

	multiSigner, err := suite.KMSCryptoMultiSigner()
	require.ErrorIs(t, err, api.ErrNotSupported)
	require.Nil(t, multiSigner)

	fixedMultiSigner, err := suite.FixedKeyMultiSigner("foo")
	require.ErrorIs(t, err, api.ErrNotSupported)
	require.Nil(t, fixedMultiSigner)
}

func TestVerify(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}
	metric := NewMockmetricsProvider(gomock.NewController(t))

	svc := New(&awsConfig, metric, "", []Opts{}...)

	err := svc.Verify(nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")

	suite := NewSuite(&awsConfig, nil, "")

	signerVerifier, err := suite.KMSCrypto()
	require.ErrorIs(t, err, api.ErrNotSupported)
	require.Nil(t, signerVerifier)

	fixedSignerVerifier, err := suite.FixedKeyCrypto(nil)
	require.ErrorIs(t, err, api.ErrNotSupported)
	require.Nil(t, fixedSignerVerifier)

	verifier, err := suite.KMSCryptoVerifier()
	require.ErrorIs(t, err, api.ErrNotSupported)
	require.Nil(t, verifier)
}

func TestImportPrivateKey(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}
	metric := NewMockmetricsProvider(gomock.NewController(t))

	svc := New(&awsConfig, metric, "", []Opts{}...)

	_, _, err := svc.ImportPrivateKey(nil, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestPubKeyBytes(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.GetPublicKeyOutput{
				PublicKey:         []byte("publickey"),
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil)
		svc := New(awsConfig, metric, "", WithAWSClient(client))

		keyID, keyType, err := svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
		require.Contains(t, string(keyID), "publickey")
		require.Contains(t, string(keyType), "ECDSAP256DER")
	})

	t.Run("success RSA", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&kms.GetPublicKeyOutput{
				PublicKey:         []byte("publickey"),
				KeySpec:           types.KeySpecRsa2048,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil)
		svc := New(awsConfig, metric, "", WithAWSClient(client))

		keyID, keyType, err := svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
		require.Contains(t, string(keyID), "publickey")
		require.Contains(t, string(keyType), "RSARS256")
	})

	t.Run("failed to export public key", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))
		client.EXPECT().GetPublicKey(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, fmt.Errorf("failed to export public key"))
		svc := New(awsConfig, metric, "", WithAWSClient(client))

		_, _, err := svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export public key")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().ExportPublicKeyCount()
		metric.EXPECT().ExportPublicKeyTime(gomock.Any())

		svc := New(awsConfig, metric, "", []Opts{}...)

		_, _, err := svc.ExportPubKeyBytes("aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestEncrypt(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().EncryptCount()
		metric.EXPECT().EncryptTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))

		suiteInterface := NewSuite(awsConfig, metric, "", WithAWSClient(client))

		suite, ok := suiteInterface.(*suiteImpl)
		assert.True(t, ok)

		crypter, err := suite.EncrypterDecrypter()
		assert.NoError(t, err)

		msg := generateNonce(64)
		encrypted := generateNonce(128)

		client.EXPECT().Encrypt(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				params *kms.EncryptInput,
				optFns ...func(*kms.Options),
			) (*kms.EncryptOutput, error) {
				assert.Equal(t, "alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147", *params.KeyId)
				assert.Equal(t, msg, params.Plaintext)
				assert.Equal(t, suite.svc.encryptionAlgo, params.EncryptionAlgorithm)

				return &kms.EncryptOutput{
					CiphertextBlob: encrypted,
				}, nil
			})

		encryptedData, nonce, err := crypter.Encrypt(
			msg,
			nil,
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
		)

		assert.NoError(t, err)
		assert.Len(t, nonce, suite.svc.nonceLength)
		assert.Equal(t, encrypted, encryptedData)
	})

	t.Run("encryption err", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().EncryptCount()
		metric.EXPECT().EncryptTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))

		svc := New(awsConfig, metric, "", WithAWSClient(client))
		msg := generateNonce(64)

		client.EXPECT().Encrypt(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				params *kms.EncryptInput,
				optFns ...func(*kms.Options),
			) (*kms.EncryptOutput, error) {
				return nil, errors.New("encryption err")
			})

		encryptedData, nonce, err := svc.Encrypt(
			msg,
			nil,
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
		)

		assert.ErrorContains(t, err, "encryption err")
		assert.Empty(t, nonce)
		assert.Empty(t, encryptedData)
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().EncryptCount()
		metric.EXPECT().EncryptTime(gomock.Any())

		svc := New(awsConfig, metric, "", []Opts{}...)

		_, _, err := svc.Encrypt(nil, nil, "aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestDecrypt(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().DecryptCount()
		metric.EXPECT().DecryptTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))

		suiteInterface := NewSuite(awsConfig, metric, "",
			WithAWSClient(client),
			WithEncryptionAlgorithm("RSAES_OAEP_SHA_256"),
		)

		suite, ok := suiteInterface.(*suiteImpl)
		assert.True(t, ok)

		crypter, err := suite.EncrypterDecrypter()
		assert.NoError(t, err)

		encrypted := generateNonce(64)
		decrypted := generateNonce(128)

		client.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				params *kms.DecryptInput,
				optFns ...func(*kms.Options),
			) (*kms.DecryptOutput, error) {
				assert.Equal(t, params.EncryptionAlgorithm, types.EncryptionAlgorithmSpec("RSAES_OAEP_SHA_256"))
				assert.Equal(t, "alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147", *params.KeyId)
				assert.Equal(t, encrypted, params.CiphertextBlob)
				assert.Equal(t, suite.svc.encryptionAlgo, params.EncryptionAlgorithm)

				return &kms.DecryptOutput{
					Plaintext: decrypted,
				}, nil
			})

		decryptedData, err := crypter.Decrypt(
			encrypted,
			nil,
			nil,
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
		)

		assert.NoError(t, err)
		assert.Equal(t, decrypted, decryptedData)
	})

	t.Run("decryption err", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().DecryptCount()
		metric.EXPECT().DecryptTime(gomock.Any())

		client := NewMockawsClient(gomock.NewController(t))

		svc := New(awsConfig, metric, "", WithAWSClient(client))
		msg := generateNonce(64)

		client.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				ctx context.Context,
				params *kms.DecryptInput,
				optFns ...func(*kms.Options),
			) (*kms.DecryptOutput, error) {
				assert.Equal(t, params.EncryptionAlgorithm, types.EncryptionAlgorithmSpec("SYMMETRIC_DEFAULT"))

				return nil, errors.New("encryption err")
			})

		decrypted, err := svc.Decrypt(
			nil,
			msg,
			nil,
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
		)

		assert.ErrorContains(t, err, "encryption err")
		assert.Empty(t, decrypted)
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		metric := NewMockmetricsProvider(gomock.NewController(t))
		metric.EXPECT().DecryptCount()
		metric.EXPECT().DecryptTime(gomock.Any())

		svc := New(awsConfig, metric, "", []Opts{}...)

		_, err := svc.Decrypt(nil, nil, nil, "aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func wrapKID(kid string) *jwk.JWK {
	out := &jwk.JWK{}
	out.KeyID = kid

	return out
}
