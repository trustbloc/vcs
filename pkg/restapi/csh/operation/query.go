/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	remotekms "github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"io"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi/models"
	zcapld2 "github.com/trustbloc/edge-service/pkg/restapi/csh/operation/zcapld"
)

func (o *Operation) ReadDocQuery(query *models.DocQuery) ([]byte, error) {
	edvOptions, err := o.edvOptions(query)
	if err != nil {
		return nil, fmt.Errorf("failed to determine edv client options: %w", err)
	}

	docReaderOptions, err := o.documentReaderOptions(query)
	if err != nil {
		return nil, fmt.Errorf("failed to determine Confidential Storage document reader options: %w", err)
	}

	contents := vault.NewDocumentReader(
		*query.VaultID,
		*query.DocID,
		o.edvClient(
			query.UpstreamAuth.Edv.BaseURL, // TODO EDV url should not be optional
			edvOptions...,
		),
		docReaderOptions...,
	)

	document := bytes.NewBuffer(nil)

	_, err = io.Copy(document, contents)

	return document.Bytes(), err
}

func (o *Operation) edvOptions(query *models.DocQuery) ([]edv.Option, error) {
	opts := make([]edv.Option, 0)

	if query.UpstreamAuth == nil || query.UpstreamAuth.Edv == nil || query.UpstreamAuth.Edv.Zcap == "" {
		return opts, nil
	}

	verMethod, err := verificationMethod(query.UpstreamAuth.Edv.Zcap)
	if err != nil {
		return nil, fmt.Errorf("failed to determine EDV verification method: %w", err)
	}

	opts = append(opts, edv.WithHeaders(zcapld2.NewHTTPSigner(
		verMethod, query.UpstreamAuth.Edv.Zcap, o.supportedSecrets(), o.supportedSignatureHashAlgorithms(),
	)))

	return opts, nil
}

func (o *Operation) documentReaderOptions(query *models.DocQuery) ([]vault.ReaderOption, error) {
	opts := make([]vault.ReaderOption, 0)

	if query.UpstreamAuth == nil || query.UpstreamAuth.Kms == nil {
		opts = append(opts, vault.WithDocumentDecrypter( // local decrypter
			jose.NewJWEDecrypt(nil, o.aries.Crypto, o.aries.KMS),
		))

		return opts, nil
	}

	kmsOptions := make([]remotekms.Opt, 0)

	if query.UpstreamAuth.Kms.Zcap != "" {
		verMethod, err := verificationMethod(query.UpstreamAuth.Kms.Zcap)
		if err != nil {
			return nil, fmt.Errorf("failed to determine KMS verification method: %w", err)
		}

		kmsOptions = append(kmsOptions, remotekms.WithHeaders(zcapld2.NewHTTPSigner(
			verMethod, query.UpstreamAuth.Kms.Zcap, o.supportedSecrets(), o.supportedSignatureHashAlgorithms(),
		)))
	}

	opts = append(opts, vault.WithDocumentDecrypter( // remote decrypter
		jose.NewJWEDecrypt(
			nil,
			o.aries.WebCrypto(
				query.UpstreamAuth.Kms.BaseURL,
				o.httpClient,
				kmsOptions...,
			),
			o.aries.WebKMS(
				query.UpstreamAuth.Kms.BaseURL,
				o.httpClient,
				kmsOptions...,
			),
		),
	))

	return opts, nil
}

func (o *Operation) supportedSecrets() httpsignatures.Secrets {
	return &zcapld2.DIDSecrets{
		Secrets: map[string]httpsignatures.Secrets{
			"key": &zcapld.AriesDIDKeySecrets{},
		},
	}
}

func (o *Operation) supportedSignatureHashAlgorithms() httpsignatures.SignatureHashAlgorithm {
	return &zcapld2.DIDSignatureHashAlgorithms{
		KMS:       o.aries.KMS,
		Crypto:    o.aries.Crypto,
		Resolvers: []zcapld2.DIDResolver{key.New()},
	}
}

func verificationMethod(compressedZCAP string) (string, error) {
	raw, err := base64URLDecodeThenGunzip(compressedZCAP)
	if err != nil {
		return "", fmt.Errorf("failed to decompress zcap: %w", err)
	}

	zcap, err := zcapld.ParseCapability(raw)
	if err != nil {
		return "", fmt.Errorf("failed to parse zcap: %w", err)
	}

	if zcap.Invoker != "" {
		return zcap.Invoker, nil
	}

	if zcap.Controller != "" {
		return zcap.Controller, nil
	}

	return "", errors.New("zcap does not specify a controller nor an invoker")
}

func base64URLDecodeThenGunzip(encoded string) ([]byte, error) {
	compressed, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode string: %w", err)
	}

	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("failed to open a new gzip reader: %w", err)
	}

	inflated := bytes.NewBuffer(nil)

	_, err = inflated.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to gunzip string: %w", err)
	}

	return inflated.Bytes(), nil
}
