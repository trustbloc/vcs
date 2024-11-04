/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/samber/lo"
	"github.com/trustbloc/kms-go/doc/jose"
	storageapi "github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"go.uber.org/zap"

	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
)

const (
	attestationStore = "attestation"
	attestationVCKey = "vc"

	jwtProofTypeHeader = "openid4vci-proof+jwt"
)

var logger = log.New("attestation-svc-client")

type Service struct {
	store               storageapi.Store
	documentLoader      ld.DocumentLoader
	signer              jose.Signer
	httpClient          *http.Client
	wallet              *wallet.Wallet
	walletDID           string
	attestationEndpoint string
}

type provider interface {
	StorageProvider() storageapi.Provider
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	CryptoSuite() api.Suite
	Wallet() *wallet.Wallet
}

func NewService(
	p provider,
	attestationEndpoint string,
	walletDIDIndex int,
) (*Service, error) {
	store, err := p.StorageProvider().OpenStore(attestationStore)
	if err != nil {
		return nil, fmt.Errorf("open attestation store: %w", err)
	}

	var didInfo *wallet.DIDInfo

	dids := p.Wallet().DIDs()

	if walletDIDIndex != -1 {
		didInfo = dids[walletDIDIndex]
	} else {
		didInfo = dids[len(dids)-1]
	}

	signer, err := p.CryptoSuite().FixedKeyMultiSigner(didInfo.KeyID)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	signatureType := p.Wallet().SignatureType()

	jwsSigner := jwssigner.NewJWSSigner(
		fmt.Sprintf("%s#%s", didInfo.ID, didInfo.KeyID),
		string(signatureType),
		kmssigner.NewKMSSigner(signer, signatureType, nil),
	)

	return &Service{
		store:               store,
		documentLoader:      p.DocumentLoader(),
		signer:              jwsSigner,
		httpClient:          p.HTTPClient(),
		wallet:              p.Wallet(),
		walletDID:           didInfo.ID,
		attestationEndpoint: attestationEndpoint,
	}, nil
}

func (s *Service) GetAttestation(ctx context.Context, req GetAttestationRequest) (string, error) {
	b, err := s.store.Get(attestationVCKey)
	if err != nil {
		if errors.Is(err, storageapi.ErrDataNotFound) {
			b, err = s.requestAttestationVC(ctx, req)
			if err != nil {
				return "", fmt.Errorf("request attestation vc: %w", err)
			}

			if err = s.store.Put(attestationVCKey, b); err != nil {
				return "", fmt.Errorf("store attestation vc: %w", err)
			}
		} else {
			return "", fmt.Errorf("get attestation vc from store: %w", err)
		}
	}

	attestationVC, err := verifiable.ParseCredential(
		b,
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
		verifiable.WithDisabledProofCheck(),
	)
	if err != nil {
		return "", fmt.Errorf("parse attestation vc: %w", err)
	}

	attestationVP, err := verifiable.NewPresentation(verifiable.WithCredentials(attestationVC))
	if err != nil {
		return "", fmt.Errorf("create vp: %w", err)
	}

	attestationVP.ID = uuid.New().String()

	if req.Nonce != "" {
		attestationVP.CustomFields = map[string]interface{}{
			"nonce": req.Nonce,
		}
	}

	var aud []string

	if req.Audience != "" {
		aud = []string{req.Audience}
	}

	claims, err := attestationVP.JWTClaims(aud, false)
	if err != nil {
		return "", fmt.Errorf("get attestation claims: %w", err)
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypeHeader,
	}

	signedJWT, err := jwt.NewJoseSigned(claims, headers, s.signer)
	if err != nil {
		return "", fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serialize signed jwt: %w", err)
	}

	return jws, nil
}

func (s *Service) requestAttestationVC(ctx context.Context, req GetAttestationRequest) ([]byte, error) {
	initResponse, err := s.attestationInit(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("attestation init: %w", err)
	}

	completeResponse, err := s.attestationComplete(
		ctx,
		initResponse.SessionID,
		initResponse.Challenge,
		req,
	)
	if err != nil {
		return nil, fmt.Errorf("attestation complete: %w", err)
	}

	return []byte(completeResponse.WalletAttestationVC), nil
}

func (s *Service) getHeaders(
	attestReq GetAttestationRequest,
) map[string]string {
	headers := map[string]string{}
	if attestReq.AuthorizationHeaderValue != "" {
		headers["Authorization"] = attestReq.AuthorizationHeaderValue
	}

	return headers
}

func (s *Service) attestationInit(
	ctx context.Context,
	attestReq GetAttestationRequest,
) (*AttestWalletInitResponse, error) {
	logger.Debug("attestation init started", zap.String("walletDID", s.walletDID))

	req := &AttestWalletInitRequest{
		Payload: map[string]interface{}{
			"type": attestReq.AttestationType,
			"application": map[string]interface{}{
				"type":    s.wallet.WalletType(),
				"name":    s.wallet.Name(),
				"version": s.wallet.Version(),
			},
			"compliance": []interface{}{
				map[string]interface{}{
					"type": s.wallet.Compliance(),
				},
			},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var resp AttestWalletInitResponse

	if err = s.doRequest(ctx, s.attestationEndpoint+"/init", body, &resp, s.getHeaders(attestReq)); err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	logger.Debug("attestation init succeeded",
		zap.String("walletDID", s.walletDID),
		zap.String("sessionID", resp.SessionID),
		zap.String("challenge", resp.Challenge),
	)

	return &resp, nil
}

func (s *Service) attestationComplete(
	ctx context.Context,
	sessionID,
	challenge string,
	attestReq GetAttestationRequest,
) (*AttestWalletCompleteResponse, error) {
	logger.Debug("attestation complete started",
		zap.String("sessionID", sessionID),
		zap.String("challenge", challenge),
	)

	claims := &JwtProofClaims{
		Issuer:   s.walletDID,
		Audience: s.attestationEndpoint,
		IssuedAt: time.Now().Unix(),
		Exp:      time.Now().Add(time.Minute * 5).Unix(),
		Nonce:    challenge,
	}

	headers := map[string]interface{}{
		jose.HeaderType: jwtProofTypeHeader,
	}

	signedJWT, err := jwt.NewJoseSigned(claims, headers, s.signer)
	if err != nil {
		return nil, fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return nil, fmt.Errorf("serialize signed jwt: %w", err)
	}

	req := &AttestWalletCompleteRequest{
		AssuranceLevel: "low",
		Proof: Proof{
			Jwt:       jws,
			ProofType: "jwt",
		},
		SessionID: sessionID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var resp AttestWalletCompleteResponse

	if err = s.doRequest(ctx, s.attestationEndpoint+"/complete", body, &resp, s.getHeaders(attestReq)); err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	logger.Debug("attestation complete succeeded",
		zap.String("sessionID", sessionID),
		zap.String("challenge", challenge),
		zap.String("attestationVC", resp.WalletAttestationVC),
	)

	fmt.Println("got attestation")
	fmt.Println(resp.WalletAttestationVC)

	return &resp, nil
}

func (s *Service) doRequest(
	ctx context.Context,
	policyURL string,
	body []byte,
	response interface{},
	headers map[string]string,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("content-type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	expectedCodes := []int{
		http.StatusOK,
		http.StatusCreated,
	}

	if !lo.Contains(expectedCodes, resp.StatusCode) {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d; response: %s", resp.StatusCode, string(b))
	}

	if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}
