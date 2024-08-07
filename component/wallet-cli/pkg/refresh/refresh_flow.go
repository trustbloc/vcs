/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package refresh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/presentation"
	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/restapi/v1/refresh"
)

type Flow struct {
	httpClient     *http.Client
	signer         *jwssigner.JWSSigner
	perfInfo       *PerfInfo
	wallet         *wallet.Wallet
	documentLoader ld.DocumentLoader
	cryptoSuite    api.Suite
	vdrRegistry    vdrapi.Registry
	history        map[string]*CredentialHistory
}

type CredentialHistory struct {
	OldCredential *verifiable.Credential
	NewCredential *verifiable.Credential
}

type PerfInfo struct {
	FullRefreshFlow time.Duration `json:"full_refresh_flow"`
}

type Opt func(opts *options)

func WithWalletDIDIndex(idx int) Opt {
	return func(opts *options) {
		opts.walletDIDIndex = idx
	}
}

type provider interface {
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	Wallet() *wallet.Wallet
	CryptoSuite() api.Suite
}

type options struct {
	walletDIDIndex int
}

func NewFlow(p provider, opts ...Opt) (*Flow, error) {
	o := &options{
		walletDIDIndex: len(p.Wallet().DIDs()) - 1,
	}

	for i := range opts {
		opts[i](o)
	}

	if o.walletDIDIndex < 0 || o.walletDIDIndex >= len(p.Wallet().DIDs()) {
		return nil, fmt.Errorf("invalid wallet did index: %d", o.walletDIDIndex)
	}

	walletDIDInfo := p.Wallet().DIDs()[o.walletDIDIndex]

	walletDID, err := did.Parse(walletDIDInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("parse wallet did: %w", err)
	}

	docResolution, err := p.VDRegistry().Resolve(walletDID.String())
	if err != nil {
		return nil, fmt.Errorf("resolve wallet did: %w", err)
	}

	signer, err := p.CryptoSuite().FixedKeyMultiSigner(walletDIDInfo.KeyID)
	if err != nil {
		return nil, fmt.Errorf("create signer for key %s: %w", walletDIDInfo.KeyID, err)
	}

	signatureType := p.Wallet().SignatureType()

	jwsSigner := jwssigner.NewJWSSigner(
		docResolution.DIDDocument.VerificationMethod[0].ID,
		string(signatureType),
		kmssigner.NewKMSSigner(signer, signatureType, nil),
	)

	return &Flow{
		httpClient:     p.HTTPClient(),
		signer:         jwsSigner,
		documentLoader: p.DocumentLoader(),
		vdrRegistry:    p.VDRegistry(),
		cryptoSuite:    p.CryptoSuite(),
		wallet:         p.Wallet(),
		history:        make(map[string]*CredentialHistory),
		perfInfo:       &PerfInfo{},
	}, nil
}

func (f *Flow) GetUpdatedCredentials() map[string]*CredentialHistory {
	return f.history
}

func (f *Flow) Run(ctx context.Context) error {
	totalFlowStart := time.Now()
	defer func() {
		f.perfInfo.FullRefreshFlow = time.Since(totalFlowStart)
	}()

	allCredentials, err := f.wallet.GetAll()
	if err != nil {
		return fmt.Errorf("get all credentials: %w", err)
	}

	var finalErr error

	for v, cred := range allCredentials {
		parsedCred, parseErr := verifiable.ParseCredential(cred,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(f.documentLoader),
		)
		if parseErr != nil {
			finalErr = errors.Join(finalErr, errors.Join(errors.New("failed to parse credential"), parseErr))
			continue
		}

		updatedCred, updatedParsedCred, updateErr := f.fetchUpdateForCred(ctx, parsedCred)

		if updateErr != nil {
			slog.Error("failed to fetch update for credential", updateErr)
			finalErr = errors.Join(finalErr, updateErr)

			continue
		}

		if updatedCred == nil {
			continue
		}

		if err = f.wallet.Delete(v); err != nil {
			return fmt.Errorf("failed to delete old credential: %w", err)
		}

		if err = f.wallet.Add(updatedCred, v); err != nil {
			return fmt.Errorf("failed to add updated credential: %w", err)
		}

		f.history[v] = &CredentialHistory{
			OldCredential: parsedCred,
			NewCredential: updatedParsedCred,
		}

		slog.Info(fmt.Sprintf("credential with key %v updated", v))
	}

	return finalErr
}

func (f *Flow) fetchUpdateForCred(ctx context.Context, parsedCred *verifiable.Credential) ([]byte, *verifiable.Credential, error) {
	credID := parsedCred.Contents().ID
	refreshService := parsedCred.Contents().RefreshService

	if refreshService == nil {
		slog.Info(fmt.Sprintf("no refresh service found for credential %s", credID))
		return nil, nil, nil
	}

	if refreshService.Type != "VerifiableCredentialRefreshService2021" {
		return nil, nil, fmt.Errorf("unexpected refresh service type: %s. Supported VerifiableCredentialRefreshService2021",
			refreshService.Type)
	}

	if refreshService.ID == "" {
		return nil, nil, fmt.Errorf("refresh service endpoint is not set")
	}

	slog.Info(fmt.Sprintf("fetching update for credential %s from %s", credID, refreshService.ID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, refreshService.ID, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create http request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("send request to refresh service: %w", err)
	}

	if resp.StatusCode == http.StatusNoContent {
		slog.Info(fmt.Sprintf("no update available for credential %s", credID))
		return nil, nil, nil
	}

	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(resp.Body) // nolint
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code %d and body: %s", resp.StatusCode, body)
	}

	var parsed refresh.CredentialRefreshAvailableResponse
	if err = json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, fmt.Errorf("parse response: %w", err)
	}

	if len(parsed.VerifiablePresentationRequest.Interact.Service) == 0 {
		return nil, nil, fmt.Errorf("no service endpoint found in presentation")
	}

	interactEndpoint := parsed.VerifiablePresentationRequest.Interact.Service[0].ServiceEndpoint

	slog.Info(fmt.Sprintf("update available for credential %s: %s", credID, credID))

	presDef, err := json.Marshal(parsed.VerifiablePresentationRequest.Query)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal presentation definition: %w", err)
	}

	queryRes, _, err := f.wallet.Query(presDef, false, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query wallet: %w", err)
	}

	if len(queryRes) != 1 {
		return nil, nil, fmt.Errorf("expected 1 presentation, got %d", len(queryRes))
	}

	signedPres, err := presentation.CreateVPToken(queryRes, &presentation.CreateVpTokenRequest{
		ClientID: parsed.VerifiablePresentationRequest.Domain,
		Nonce:    parsed.VerifiablePresentationRequest.Challenge,
		VPFormats: &presexch.Format{
			JwtVP: &presexch.JwtType{},
		},
		Wallet:      f.wallet,
		CryptoSuite: f.cryptoSuite,
		VdrRegistry: f.vdrRegistry,
	})
	if err != nil {
		return nil, nil, errors.Join(errors.New("failed to sign presentation"), err)
	}

	reqBody, err := json.Marshal(refresh.GetRefreshedCredentialReq{
		VerifiablePresentation: []byte(signedPres[0]),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	slog.Info(fmt.Sprintf("sending request to interact endpoint %s", interactEndpoint))

	req, err = http.NewRequestWithContext(ctx, http.MethodPost,
		interactEndpoint,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err = f.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("send request to interact service: %w", err)
	}

	body = nil
	if resp.Body != nil {
		body, _ = io.ReadAll(resp.Body) // nolint
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code %d and body: %s", resp.StatusCode, body)
	}

	var refreshedCredResp refresh.GetRefreshedCredentialResp
	if err = json.Unmarshal(body, &refreshedCredResp); err != nil {
		return nil, nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var rawUpdatedCred []byte

	switch v := refreshedCredResp.VerifiableCredential.(type) {
	case []byte:
		rawUpdatedCred = v
	case string:
		rawUpdatedCred = []byte(v)
	default:
		rawUpdatedCred, err = json.Marshal(v)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal updated credential: %w", err)
		}
	}

	newParsedCred, err := verifiable.ParseCredential(rawUpdatedCred, verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse updated credential: %w", err)
	}

	slog.Info(fmt.Sprintf("received updated credential. old id : %v new id: %v", credID,
		newParsedCred.Contents().ID))

	return rawUpdatedCred, newParsedCred, nil
}
