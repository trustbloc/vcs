/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
)

// Service to provide zcapld functionality
type Service struct {
	keyManager kms.KeyManager
	crypto     cryptoapi.Crypto
}

// New return zcap service
func New(keyManager kms.KeyManager, crypto cryptoapi.Crypto) *Service {
	return &Service{keyManager: keyManager, crypto: crypto}
}

// CreateDIDKey create did key
func (s *Service) CreateDIDKey() (string, error) {
	signer, err := signature.NewCryptoSigner(s.crypto, s.keyManager, kms.ED25519)
	if err != nil {
		return "", fmt.Errorf("failed to create crypto signer: %w", err)
	}

	_, didKeyURL := fingerprint.CreateDIDKey(signer.PublicKeyBytes())

	return didKeyURL, nil
}

// SignHeader sign header
func (s *Service) SignHeader(req *http.Request, capabilityBytes []byte,
	verificationMethod string) (*http.Header, error) {
	capability, err := zcapld.ParseCapability(capabilityBytes)
	if err != nil {
		return nil, err
	}

	compressedZcap, err := compressZCAP(capability)
	if err != nil {
		return nil, err
	}

	req.Header.Set(zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`, compressedZcap, "read"))

	hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
	hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
		Crypto: s.crypto,
		KMS:    s.keyManager,
	})

	err = hs.Sign(verificationMethod, req)
	if err != nil {
		return nil, err
	}

	return &req.Header, nil
}

func compressZCAP(zcap *zcapld.Capability) (string, error) {
	raw, err := json.Marshal(zcap)
	if err != nil {
		return "", err
	}

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}
