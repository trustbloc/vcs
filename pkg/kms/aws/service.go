/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination service_mocks.go -package aws -source=service.go

package aws

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/btcsuite/btcd/btcec"
	arieskms "github.com/trustbloc/kms-go/spi/kms"
)

type awsClient interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput,
		optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput,
		optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	CreateKey(ctx context.Context, params *kms.CreateKeyInput,
		optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(ctx context.Context, params *kms.CreateAliasInput,
		optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	ScheduleKeyDeletion(ctx context.Context, params *kms.ScheduleKeyDeletionInput,
		optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
}

type metricsProvider interface {
	SignCount()
	EncryptCount()
	DecryptCount()
	SignTime(value time.Duration)
	EncryptTime(value time.Duration)
	DecryptTime(value time.Duration)
	ExportPublicKeyCount()
	ExportPublicKeyTime(value time.Duration)
	VerifyCount()
	VerifyTime(value time.Duration)
}

type ecdsaSignature struct {
	R, S *big.Int
}

// Service aws kms.
type Service struct {
	options          *opts
	client           awsClient
	metrics          metricsProvider
	healthCheckKeyID string
	encryptionAlgo   types.EncryptionAlgorithmSpec
	nonceLength      int
}

const (
	signingAlgorithmEcdsaSha256 = "ECDSA_SHA_256"
	signingAlgorithmEcdsaSha384 = "ECDSA_SHA_384"
	signingAlgorithmEcdsaSha512 = "ECDSA_SHA_512"
	bitSize                     = 8
)

// nolint: gochecknoglobals
var kmsKeyTypes = map[types.SigningAlgorithmSpec]arieskms.KeyType{
	signingAlgorithmEcdsaSha256:                    arieskms.ECDSAP256DER,
	signingAlgorithmEcdsaSha384:                    arieskms.ECDSAP384DER,
	signingAlgorithmEcdsaSha512:                    arieskms.ECDSAP521DER,
	types.SigningAlgorithmSpecRsassaPkcs1V15Sha256: arieskms.RSARS256,
}

// nolint: gochecknoglobals
var keySpecToCurve = map[types.KeySpec]elliptic.Curve{
	types.KeySpecEccSecgP256k1: btcec.S256(),
}

const (
	defaultNonceLength = 16
)

// New return aws service.
func New(
	awsConfig *aws.Config,
	metrics metricsProvider,
	healthCheckKeyID string,
	opts ...Opts,
) *Service {
	options := newOpts()

	for _, opt := range opts {
		opt(options)
	}

	client := options.awsClient
	if client == nil {
		var awsOptions []func(*kms.Options)
		if options.endpointResolver != nil {
			awsOptions = append(awsOptions, kms.WithEndpointResolverV2(options.endpointResolver))
		}

		client = kms.NewFromConfig(*awsConfig, awsOptions...)
	}

	algo := types.EncryptionAlgorithmSpecSymmetricDefault
	if options.encryptionAlgorithm != "" {
		algo = types.EncryptionAlgorithmSpec(options.encryptionAlgorithm)
	}

	return &Service{
		options:          options,
		client:           client,
		metrics:          metrics,
		healthCheckKeyID: healthCheckKeyID,
		encryptionAlgo:   algo,
		nonceLength:      defaultNonceLength,
	}
}

// TODO this API swapped cipher and aad, so dataprotect passed them in swapped
//  I fixed that, but if any other code uses the aws wrapper's Decrypt, it would also need changing

// Decrypt data.
func (s *Service) Decrypt(cipher, _, _ []byte, kh interface{}) ([]byte, error) {
	startTime := time.Now()

	defer func() {
		if s.metrics != nil {
			s.metrics.DecryptTime(time.Since(startTime))
		}
	}()

	if s.metrics != nil {
		s.metrics.DecryptCount()
	}

	keyID, err := s.getKeyID(kh.(string))
	if err != nil {
		return nil, err
	}

	input := &kms.DecryptInput{
		CiphertextBlob:      cipher,
		EncryptionAlgorithm: s.encryptionAlgo,
		KeyId:               aws.String(keyID),
	}

	resp, err := s.client.Decrypt(context.Background(), input)
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
}

// Encrypt data.
func (s *Service) Encrypt(
	msg []byte,
	_ []byte,
	kh interface{},
) ([]byte, []byte, error) {
	startTime := time.Now()

	defer func() {
		if s.metrics != nil {
			s.metrics.EncryptTime(time.Since(startTime))
		}
	}()

	if s.metrics != nil {
		s.metrics.EncryptCount()
	}

	keyID, err := s.getKeyID(kh.(string))
	if err != nil {
		return nil, nil, err
	}

	input := &kms.EncryptInput{
		KeyId:               aws.String(keyID),
		Plaintext:           msg,
		EncryptionAlgorithm: s.encryptionAlgo,
	}

	resp, err := s.client.Encrypt(context.Background(), input)
	if err != nil {
		return nil, nil, err
	}

	return resp.CiphertextBlob, generateNonce(s.nonceLength), nil
}

// Sign data.
func (s *Service) Sign(msg []byte, kh interface{}) ([]byte, error) { //nolint: funlen
	startTime := time.Now()

	defer func() {
		if s.metrics != nil {
			s.metrics.SignTime(time.Since(startTime))
		}
	}()

	if s.metrics != nil {
		s.metrics.SignCount()
	}

	keyID, err := s.getKeyID(kh.(string))
	if err != nil {
		return nil, err
	}

	describeKey, err := s.client.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, err
	}

	signAlgo := s.selectSignAlgo(describeKey.KeyMetadata.KeySpec, describeKey.KeyMetadata.SigningAlgorithms)

	digest, err := hashMessage(msg, signAlgo)
	if err != nil {
		return nil, err
	}

	input := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signAlgo,
	}

	result, err := s.client.Sign(context.Background(), input)
	if err != nil {
		return nil, err
	}

	if describeKey.KeyMetadata.KeySpec == types.KeySpecEccSecgP256k1 ||
		describeKey.KeyMetadata.KeySpec == types.KeySpecEccNistP384 ||
		describeKey.KeyMetadata.KeySpec == types.KeySpecEccNistP256 {
		signature := ecdsaSignature{}

		_, err = asn1.Unmarshal(result.Signature, &signature)
		if err != nil {
			return nil, err
		}

		curveBits := keySpecToCurve[describeKey.KeyMetadata.KeySpec].Params().BitSize

		keyBytes := curveBits / bitSize
		if curveBits%bitSize > 0 {
			keyBytes++
		}

		copyPadded := func(source []byte, size int) []byte {
			dest := make([]byte, size)
			copy(dest[size-len(source):], source)

			return dest
		}

		return append(copyPadded(signature.R.Bytes(), keyBytes), copyPadded(signature.S.Bytes(), keyBytes)...), nil
	}

	return result.Signature, nil
}

// Get key handle.
func (s *Service) Get(keyID string) (interface{}, error) {
	return keyID, nil
}

// HealthCheck check kms.
func (s *Service) HealthCheck() error {
	keyID, err := s.getKeyID(s.healthCheckKeyID)
	if err != nil {
		return err
	}

	_, err = s.client.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return err
	}

	return nil
}

// ExportPubKeyBytes export public key.
func (s *Service) ExportPubKeyBytes(keyURI string) ([]byte, arieskms.KeyType, error) {
	startTime := time.Now()

	defer func() {
		if s.metrics != nil {
			s.metrics.ExportPublicKeyTime(time.Since(startTime))
		}
	}()

	if s.metrics != nil {
		s.metrics.ExportPublicKeyCount()
	}

	keyID, err := s.getKeyID(keyURI)
	if err != nil {
		return nil, "", err
	}

	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	}

	result, err := s.client.GetPublicKey(context.Background(), input)
	if err != nil {
		return nil, "", err
	}

	return result.PublicKey, kmsKeyTypes[s.selectSignAlgo(result.KeySpec, result.SigningAlgorithms)], nil
}

func (s *Service) selectSignAlgo(keyType types.KeySpec, algo []types.SigningAlgorithmSpec) types.SigningAlgorithmSpec {
	switch keyType { //nolint:exhaustive
	case types.KeySpecRsa2048, types.KeySpecRsa3072, types.KeySpecRsa4096:
		return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	default:
		return algo[0]
	}
}

// Verify signature.
func (s *Service) Verify(_, _ []byte, _ interface{}) error {
	return fmt.Errorf("not implemented")
}

// Create key.
func (s *Service) Create(kt arieskms.KeyType) (string, interface{}, error) {
	keyUsage := types.KeyUsageTypeSignVerify

	var keySpec types.KeySpec

	switch string(kt) {
	case arieskms.ED25519:
		keySpec = types.KeySpecEccNistP256
	case arieskms.ECDSAP256DER:
		keySpec = types.KeySpecEccNistP256
	case arieskms.ECDSAP384DER:
		keySpec = types.KeySpecEccNistP384
	case arieskms.ECDSAP521DER:
		keySpec = types.KeySpecEccNistP521
	case arieskms.ECDSASecp256k1DER:
		keySpec = types.KeySpecEccSecgP256k1
	case arieskms.RSARS256:
		keySpec = types.KeySpecRsa2048
	default:
		return "", nil, fmt.Errorf("key not supported %s", kt)
	}

	result, err := s.client.CreateKey(context.Background(),
		&kms.CreateKeyInput{KeySpec: keySpec, KeyUsage: keyUsage})
	if err != nil {
		return "", nil, err
	}

	aliasPrefix := s.options.KeyAliasPrefix()
	if strings.TrimSpace(aliasPrefix) != "" {
		aliasName := fmt.Sprintf("alias/%s_%s", aliasPrefix, *result.KeyMetadata.KeyId)

		_, err = s.client.CreateAlias(context.Background(),
			&kms.CreateAliasInput{AliasName: &aliasName, TargetKeyId: result.KeyMetadata.KeyId})
		if err != nil {
			return "", nil, err
		}
	}

	return *result.KeyMetadata.KeyId, *result.KeyMetadata.KeyId, nil
}

// CreateAndExportPubKeyBytes create and export key.
func (s *Service) CreateAndExportPubKeyBytes(kt arieskms.KeyType, _ ...arieskms.KeyOpts) (string, []byte, error) {
	keyID, _, err := s.Create(kt)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, _, err := s.ExportPubKeyBytes(keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, pubKeyBytes, nil
}

// Remove removes kms key referenced by keyURI from KMS.
func (s *Service) Remove(keyURI string) error {
	keyID, err := s.getKeyID(keyURI)
	if err != nil {
		return err
	}

	_, err = s.client.ScheduleKeyDeletion(context.Background(), &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(keyID),
	})

	return err
}

// ImportPrivateKey private key.
func (s *Service) ImportPrivateKey(_ interface{}, _ arieskms.KeyType,
	_ ...arieskms.PrivateKeyOpts) (string, interface{}, error) {
	return "", nil, fmt.Errorf("not implemented")
}

// SignMulti sign multi.
func (s *Service) SignMulti(_ [][]byte, _ interface{}) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *Service) getKeyID(keyURI string) (string, error) {
	if !strings.Contains(keyURI, "aws-kms") {
		return keyURI, nil
	}

	// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
	// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
	re1 := regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):([a-z0-9-]+):key/(.+)`)

	if strings.Contains(keyURI, "alias") {
		re1 = regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):([a-z0-9-]+):(.+)`)
	}

	r := re1.FindStringSubmatch(keyURI)

	const subStringCount = 5

	if len(r) != subStringCount {
		return "", fmt.Errorf("extracting key id from URI failed")
	}

	return r[4], nil
}

func generateNonce(length int) []byte {
	key := make([]byte, length)
	_, _ = rand.Read(key) //nolint: errcheck

	return key
}

func hashMessage(message []byte, algorithm types.SigningAlgorithmSpec) ([]byte, error) {
	var digest hash.Hash

	switch algorithm { //nolint: exhaustive
	case signingAlgorithmEcdsaSha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		digest = sha256.New()
	case signingAlgorithmEcdsaSha384:
		digest = sha512.New384()
	case signingAlgorithmEcdsaSha512:
		digest = sha512.New()
	default:
		return []byte{}, fmt.Errorf("unknown signing algorithm - %v", algorithm)
	}

	digest.Write(message)

	return digest.Sum(nil), nil
}
