/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcskms

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	mockwrapper "github.com/trustbloc/kms-go/mock/wrapper"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/kms/signer"
)

// MockKMS mocks kms.VCSKeyManager.
//
// Set either MockKMS.Signer or MockKMS.FixedSigner.
type MockKMS struct {
	Signer      api.KMSCryptoMultiSigner
	FixedSigner api.FixedKeyMultiSigner
	VCSignerErr error
	KeyTypes    []kmsapi.KeyType
}

// NewVCSigner mock.
func (m *MockKMS) NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	if m.VCSignerErr != nil {
		return nil, m.VCSignerErr
	}

	var (
		fks api.FixedKeyMultiSigner
		err error
	)

	switch {
	case m.FixedSigner != nil:
		fks = m.FixedSigner
	case m.Signer != nil:
		fks, err = m.Signer.FixedMultiSignerGivenKID(creator)
		if err != nil {
			return nil, err
		}
	default:
		fks = &mockwrapper.MockFixedKeyCrypto{}
	}

	return signer.NewKMSSignerBBS(fks, signatureType, nil), nil
}

// SupportedKeyTypes unimplemented stub.
func (m *MockKMS) SupportedKeyTypes() []kmsapi.KeyType {
	return m.KeyTypes
}

// CreateJWKKey unimplemented stub.
func (m *MockKMS) CreateJWKKey(_ kmsapi.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}

// CreateCryptoKey unimplemented stub.
func (m *MockKMS) CreateCryptoKey(_ kmsapi.KeyType) (string, interface{}, error) {
	return "", nil, nil
}

var _ kms.VCSKeyManager = &MockKMS{}
