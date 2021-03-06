/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/kms/pkg/restapi/kms/operation"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
	zcapld2 "github.com/trustbloc/edge-service/pkg/restapi/csh/operation/zcapld"
)

// ReadDocQuery resolves a DocQuery to the contents of a Confidential Storage document.
func (o *Operation) ReadDocQuery(query *openapi.DocQuery) ([]byte, error) {
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

func (o *Operation) edvOptions(query *openapi.DocQuery) ([]edv.Option, error) {
	opts := []edv.Option{edv.WithHTTPClient(o.httpClient)}

	if query.UpstreamAuth.Edv == nil || query.UpstreamAuth.Edv.Zcap == "" {
		return opts, nil
	}

	verMethod, err := invoker(query.UpstreamAuth.Edv.Zcap)
	if err != nil {
		return nil, fmt.Errorf("failed to determine EDV verification method: %w", err)
	}

	opts = append(opts, edv.WithHeaders(zcapld2.NewHTTPSigner(
		verMethod,
		query.UpstreamAuth.Edv.Zcap,
		func(r *http.Request) (string, error) {
			action := "write"

			if r.Method == http.MethodGet {
				action = "read"
			}

			return action, nil
		},
		o.supportedSecrets(),
		o.supportedSignatureHashAlgorithms(),
	)))

	return opts, nil
}

func (o *Operation) documentReaderOptions(query *openapi.DocQuery) ([]vault.ReaderOption, error) {
	opts := make([]vault.ReaderOption, 0)

	if query.UpstreamAuth.Kms == nil {
		opts = append(opts, vault.WithDocumentDecrypter( // local decrypter
			jose.NewJWEDecrypt(nil, o.aries.Crypto, o.aries.KMS),
		))

		return opts, nil
	}

	kmsOptions := make([]webkms.Opt, 0)

	if query.UpstreamAuth.Kms.Zcap != "" {
		verMethod, err := invoker(query.UpstreamAuth.Kms.Zcap)
		if err != nil {
			return nil, fmt.Errorf("failed to determine KMS verification method: %w", err)
		}

		kmsOptions = append(kmsOptions,
			webkms.WithHeaders(zcapld2.NewHTTPSigner(
				verMethod,
				query.UpstreamAuth.Kms.Zcap,
				operation.CapabilityInvocationAction,
				o.supportedSecrets(),
				o.supportedSignatureHashAlgorithms(),
			),
			))
	}

	path, err := keystorePath(query.UpstreamAuth.Kms.Zcap)
	if err != nil {
		return nil, fmt.Errorf("failed to determine remote keystore relative path: %w", err)
	}

	// TODO this is a scary hack: seems like the REST API message needs to include the remote keystore's
	//  URI in a separate field in order to support scenarios with remote KMS but no zcaps.
	//  Also it would decouple the CHS from the invocation target ID on the KMS zcap:
	//  https://github.com/trustbloc/edge-service/issues/613.
	keystoreURL := query.UpstreamAuth.Kms.BaseURL + path

	opts = append(opts, vault.WithDocumentDecrypter( // remote decrypter
		jose.NewJWEDecrypt(
			nil,
			o.aries.WebCrypto(
				keystoreURL,
				o.httpClient,
				kmsOptions...,
			),
			o.aries.WebKMS(
				keystoreURL,
				o.httpClient,
				kmsOptions...,
			),
		),
	))

	return opts, nil
}

// TODO make supported zcapld algorithms and secret stores configurable
func (o *Operation) supportedSecrets() httpsignatures.Secrets {
	return &zcapld.AriesDIDKeySecrets{}
}

func (o *Operation) supportedSignatureHashAlgorithms() httpsignatures.SignatureHashAlgorithm {
	return &zcapld2.DIDSignatureHashAlgorithms{
		KMS:       o.aries.KMS,
		Crypto:    o.aries.Crypto,
		Resolvers: o.aries.DIDResolvers,
	}
}

func invoker(compressedZCAP string) (string, error) {
	zcap, err := zcapld.DecompressZCAP(compressedZCAP)
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

func keystorePath(compressedZCAP string) (string, error) {
	zcap, err := zcapld.DecompressZCAP(compressedZCAP)
	if err != nil {
		return "", fmt.Errorf("failed to parse zcap: %w", err)
	}

	u, err := url.Parse(zcap.InvocationTarget.ID)
	if err != nil {
		return "", fmt.Errorf("failed to parse zcap invocation target id: %w", err)
	}

	return u.Path, nil
}
