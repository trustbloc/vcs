/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/method/web"
	"github.com/trustbloc/did-go/vdr"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	longform "github.com/trustbloc/sidetree-go/pkg/vdr/sidetreelongform"
)

func NewRegistry(tls *tls.Config) (vdrapi.Registry, error) {
	var opts []vdr.Option

	longForm, err := longform.New()
	if err != nil {
		return nil, err
	}

	opts = append(opts,
		vdr.WithVDR(longForm),
		vdr.WithVDR(key.New()),
		vdr.WithVDR(jwk.New()),
		vdr.WithVDR(
			&webVDR{
				http: &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: tls,
					},
				},
				VDR: web.New(),
			},
		),
	)

	return vdr.New(opts...), nil
}

type webVDR struct {
	http *http.Client
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	docRes, err := w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
	if err != nil {
		return nil, fmt.Errorf("failed to read did web: %w", err)
	}

	return docRes, nil
}
