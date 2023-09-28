/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// NewSuite returns a api.Suite built on top of aws kms.
func NewSuite(awsConfig *aws.Config,
	metrics metricsProvider,
	healthCheckKeyID string,
	opts ...Opts) api.Suite {
	svc := New(awsConfig, metrics, healthCheckKeyID, opts...)

	return &suiteImpl{
		svc: svc,
	}
}

type suiteImpl struct {
	svc *Service
}

func (s *suiteImpl) KeyCreator() (api.KeyCreator, error) {
	return &keyCreator{svc: s.svc}, nil
}

func (s *suiteImpl) RawKeyCreator() (api.RawKeyCreator, error) {
	return &keyCreator{svc: s.svc}, nil
}

type keyCreator struct {
	svc *Service
}

func (c *keyCreator) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	kid, pkBytes, err := c.svc.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, err
	}

	pk, err := jwksupport.PubKeyBytesToJWK(pkBytes, keyType)
	if err != nil {
		return nil, err
	}

	pk.KeyID = kid

	return pk, nil
}

func (c *keyCreator) CreateRaw(keyType kms.KeyType) (string, interface{}, error) {
	kid, pkBytes, err := c.svc.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return "", nil, err
	}

	pk, err := jwksupport.PubKeyBytesToKey(pkBytes, keyType)
	if err != nil {
		return "", nil, err
	}

	return kid, pk, nil
}

func (s *suiteImpl) KMSCrypto() (api.KMSCrypto, error) {
	return nil, api.ErrNotSupported
}

func (s *suiteImpl) FixedKeyCrypto(*jwk.JWK) (api.FixedKeyCrypto, error) {
	return nil, api.ErrNotSupported
}

func (s *suiteImpl) KMSCryptoVerifier() (api.KMSCryptoVerifier, error) {
	return nil, api.ErrNotSupported
}

func (s *suiteImpl) KMSCryptoSigner() (api.KMSCryptoSigner, error) {
	return &signer{svc: s.svc}, nil
}

type signer struct {
	svc *Service
}

func (s *signer) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	return s.svc.Sign(msg, pub.KeyID)
}

func (s *signer) FixedKeySigner(pub *jwk.JWK) (api.FixedKeySigner, error) {
	return &fixedKeySigner{svc: s.svc, kid: pub.KeyID}, nil
}

func (s *suiteImpl) FixedKeySigner(kid string) (api.FixedKeySigner, error) {
	return &fixedKeySigner{svc: s.svc, kid: kid}, nil
}

func (s *suiteImpl) KMSCryptoMultiSigner() (api.KMSCryptoMultiSigner, error) {
	return nil, api.ErrNotSupported
}

func (s *suiteImpl) FixedKeyMultiSigner(string) (api.FixedKeyMultiSigner, error) {
	return nil, api.ErrNotSupported
}

type fixedKeySigner struct {
	svc *Service
	kid string
}

func (f *fixedKeySigner) Sign(msg []byte) ([]byte, error) {
	return f.svc.Sign(msg, f.kid)
}

func (s *suiteImpl) EncrypterDecrypter() (api.EncrypterDecrypter, error) {
	return &encDec{svc: s.svc}, nil
}

type encDec struct {
	svc *Service
}

func (e *encDec) Encrypt(msg, aad []byte, kid string) ([]byte, []byte, error) {
	return e.svc.Encrypt(msg, aad, kid)
}

func (e *encDec) Decrypt(cipher, aad, nonce []byte, kid string) ([]byte, error) {
	return e.svc.Decrypt(cipher, aad, nonce, kid)
}
