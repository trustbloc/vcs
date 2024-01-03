/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	tlsutils "github.com/trustbloc/cmdutil-go/pkg/utils/tls"
	utiltime "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/verifiable"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	vcsAPIGateway        = "https://api-gateway.trustbloc.local:8080"
	issueCredentialURL   = vcsAPIGateway + "/issuer/profiles/i_myprofile_jwt_client_attestation/v1.0/credentials/issue"
	oidcProviderURL      = "http://cognito-auth.local:8094/cognito"
	oidcProviderUsername = "profile-user-issuer-1"
	oidcProviderPassword = "profile-user-issuer-1-pwd"
)

type sessionMetadata struct {
	challenge string
	walletDID string
}

type server struct {
	router     *mux.Router
	httpClient *http.Client
	sessions   sync.Map // sessionID -> sessionMetadata
}

func newServer() *server {
	router := mux.NewRouter()

	rootCAs, err := tlsutils.GetCertPool(false, []string{os.Getenv("ROOT_CA_CERTS_PATH")})
	if err != nil {
		panic(err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	srv := &server{
		router:     router,
		httpClient: httpClient,
	}

	router.HandleFunc("/profiles/profileID/profileVersion/wallet/attestation/init", srv.evaluateWalletAttestationInitRequest).Methods(http.MethodPost)
	router.HandleFunc("/profiles/profileID/profileVersion/wallet/attestation/complete", srv.evaluateWalletAttestationCompleteRequest).Methods(http.MethodPost)

	return srv
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) evaluateWalletAttestationInitRequest(w http.ResponseWriter, r *http.Request) {
	var request AttestWalletInitRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.writeResponse(
			w, http.StatusBadRequest, fmt.Sprintf("decode wallet attestation init request: %s", err.Error()))

		return
	}

	log.Printf("handling request: %s with payload %v", r.URL.String(), request)

	if !reflect.DeepEqual(request.Assertions, []string{"wallet_authentication"}) {
		s.writeResponse(
			w, http.StatusBadRequest, "assertions field is invalid")

		return
	}

	if !reflect.DeepEqual(request.WalletMetadata, map[string]interface{}{"wallet_name": "wallet-cli"}) {
		s.writeResponse(
			w, http.StatusBadRequest, "walletMetadata field is invalid")

		return
	}

	walletDID, ok := request.WalletAuthentication["wallet_id"].(string)
	if len(request.WalletAuthentication) != 1 || !ok || walletDID == "" {
		s.writeResponse(
			w, http.StatusBadRequest, "walletAuthentication field is invalid")

		return
	}

	sessionID, challenge := uuid.NewString(), uuid.NewString()

	response := &AttestWalletInitResponse{
		Challenge: challenge,
		SessionID: sessionID,
	}

	s.sessions.Store(sessionID, sessionMetadata{
		challenge: challenge,
		walletDID: walletDID,
	})

	go func() {
		time.Sleep(5 * time.Minute)
		s.sessions.Delete(sessionID)

		log.Printf("session %s is deleted", sessionID)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("failed to write response: %s", err.Error())
	}
}

func (s *server) evaluateWalletAttestationCompleteRequest(w http.ResponseWriter, r *http.Request) {
	var request AttestWalletCompleteRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.writeResponse(
			w, http.StatusBadRequest, fmt.Sprintf("decode wallet attestation init request: %s", err.Error()))

		return
	}

	log.Printf("handling request: %s with payload %v", r.URL.String(), request)

	if request.AssuranceLevel != "low" {
		s.writeResponse(w, http.StatusBadRequest, "assuranceLevel field is invalid")

		return
	}

	if request.Proof.ProofType != "jwt" {
		s.writeResponse(w, http.StatusBadRequest, "proof.ProofType field is invalid")

		return
	}

	walletDID, err := s.evaluateWalletProofJWT(request.SessionID, request.Proof.Jwt)
	if err != nil {
		s.writeResponse(w, http.StatusBadRequest, err.Error())

		return
	}

	attestationVC, err := s.attestationVC(context.Background(), walletDID)
	if err != nil {
		s.writeResponse(w, http.StatusInternalServerError, err.Error())

		return
	}

	response := &AttestWalletCompleteResponse{
		WalletAttestationVC: attestationVC,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("failed to write response: %s", err.Error())
	}
}

func (s *server) evaluateWalletProofJWT(
	sessionID, proofJWT string,
) (string, error) {
	jwtParsed, _, err := jwt.Parse(proofJWT)
	if err != nil {
		return "", fmt.Errorf("parse request.Proof.Jwt: %s", err.Error())
	}

	var jwtProofClaims JwtProofClaims
	err = jwtParsed.DecodeClaims(&jwtProofClaims)
	if err != nil {
		return "", fmt.Errorf("decode request.Proof.Jwt: %s", err.Error())
	}

	var sessionData sessionMetadata
	sessionDataIface, ok := s.sessions.Load(sessionID)
	if ok {
		sessionData, ok = sessionDataIface.(sessionMetadata)
	}

	if !ok {
		return "", fmt.Errorf("session %s is unknown", sessionID)
	}

	if jwtProofClaims.Issuer != sessionData.walletDID {
		return "", fmt.Errorf("jwtProofClaims.Issuer is invalid, got: %s, want: %s", jwtProofClaims.Issuer, sessionData.walletDID)
	}

	if jwtProofClaims.Audience == "" {
		return "", fmt.Errorf("jwtProofClaims.Audience is empty")
	}

	now := time.Now()
	if now.Before(time.Unix(jwtProofClaims.IssuedAt, 0)) {
		return "", fmt.Errorf("jwtProofClaims.IssuedAt is invalid")
	}

	if now.After(time.Unix(jwtProofClaims.Exp, 0)) {
		return "", fmt.Errorf("jwtProofClaims.Exp is invalid")
	}

	if jwtProofClaims.Nonce != sessionData.challenge {
		return "", fmt.Errorf("jwtProofClaims.Nonce is invalid, got: %s, want: %s", jwtProofClaims.Nonce, sessionData.challenge)
	}

	return jwtProofClaims.Issuer, nil
}

func (s *server) attestationVC(ctx context.Context, walletDID string) (string, error) {
	vcc := verifiable.CredentialContents{
		Context: []string{
			verifiable.ContextURI,
			"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
		},
		ID: uuid.New().String(),
		Types: []string{
			verifiable.VCType,
			"WalletAttestationCredential",
		},
		Subject: []verifiable.Subject{
			{
				ID: walletDID,
			},
		},
		Issuer: &verifiable.Issuer{
			ID: walletDID,
		},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Expired: &utiltime.TimeWrapper{
			Time: time.Now().Add(time.Hour),
		},
	}

	vc, err := verifiable.CreateCredential(vcc, nil)
	if err != nil {
		return "", fmt.Errorf("create attestation vc: %w", err)
	}

	claims, err := vc.JWTClaims(false)
	if err != nil {
		return "", fmt.Errorf("get jwt claims: %w", err)
	}

	unsecuredJWT, err := claims.MarshalUnsecuredJWT()
	if err != nil {
		return "", fmt.Errorf("marshal unsecured jwt: %w", err)
	}

	issueCredentialData := &IssueCredentialData{
		Credential: unsecuredJWT,
	}

	body, err := json.Marshal(issueCredentialData)
	if err != nil {
		return "", fmt.Errorf("marshal issue credential request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issueCredentialURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	token, err := s.issueAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("issue access token: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d; response: %s", resp.StatusCode, string(b))
	}

	return string(b), nil
}

func (s *server) issueAccessToken(ctx context.Context) (string, error) {
	conf := clientcredentials.Config{
		TokenURL:     oidcProviderURL + "/oauth2/token",
		ClientID:     oidcProviderUsername,
		ClientSecret: oidcProviderPassword,
		Scopes:       []string{"org_admin"},
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)

	token, err := conf.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("get access token: %w", err)
	}

	fmt.Printf("token: %v\n", token)

	return token.Extra("id_token").(string), nil
}

// writeResponse writes interface value to response
func (s *server) writeResponse(
	rw http.ResponseWriter,
	status int,
	msg string,
) {
	log.Printf("[%d]   %s", status, msg)

	rw.WriteHeader(status)

	_, _ = rw.Write([]byte(msg))
}
