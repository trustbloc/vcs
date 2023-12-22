/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/trustbloc/vc-go/jwt"
)

const (
	attestationVCJWT = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDppb246RWlDSkhLS3h6ekU2WmpLOWpBRkRoRk1tWE5RZVFwWDZGUFVweDBjdjBtZTZ4UTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNklqQmxNamcwT1dObExURTBNMlV0TkdGa01TMWlZalF6TFRVeFl6QTVPR1EyTldVNVl5SXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10cFpDSTZJakJsTWpnME9XTmxMVEUwTTJVdE5HRmtNUzFpWWpRekxUVXhZekE1T0dRMk5XVTVZeUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa2hQTW5ObWN6QnhaR05ZZEVkbmJWSnpiREJSWDJKNFQzcHNaMFpIU2tKUWNEUlFkM05JV1RKdFoyTWlMQ0o1SWpvaVdVeFVRMUpTZVhreFJrRjVSV2RFY2pCRWVsZDFjekZFYkY5UFgyWk5iR1paU25keVRYQk1TMWxSUlNKOUxDSndkWEp3YjNObGN5STZXeUpoZFhSb1pXNTBhV05oZEdsdmJpSXNJbUZ6YzJWeWRHbHZiazFsZEdodlpDSmRMQ0owZVhCbElqb2lTbk52YmxkbFlrdGxlVEl3TWpBaWZWMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFF6QklTSEIyTjB0VmJVbHlkVUZaTmtKbU1XUXROV3BXU1UxT1JIcG1lbEpUWkUwMFYwaDZiRWQxWDFFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVVJsUkhGVlUyOVZRMnAxWkZVNE9URmtZM0JoVDJaWU1VeHZhRXRVVFVwZldqUlVUbXR6VUdGWmVHUlJJaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbEVNWGszUVd0TmJIWnJNSGg1UWpoYVRrcEpRbk53TmpWR1luRjNibEpvWkZsM1pHcEVjMHhuU214NFFTSjlMQ0owZVhCbElqb2lZM0psWVhSbEluMCMwZTI4NDljZS0xNDNlLTRhZDEtYmI0My01MWMwOThkNjVlOWMifQ.eyJpYXQiOjE3MDAyMTkyMjEsImlzcyI6ImRpZDppb246RWlDSkhLS3h6ekU2WmpLOWpBRkRoRk1tWE5RZVFwWDZGUFVweDBjdjBtZTZ4UTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKaFpHUXRjSFZpYkdsakxXdGxlWE1pTENKd2RXSnNhV05MWlhseklqcGJleUpwWkNJNklqQmxNamcwT1dObExURTBNMlV0TkdGa01TMWlZalF6TFRVeFl6QTVPR1EyTldVNVl5SXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10cFpDSTZJakJsTWpnME9XTmxMVEUwTTJVdE5HRmtNUzFpWWpRekxUVXhZekE1T0dRMk5XVTVZeUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa2hQTW5ObWN6QnhaR05ZZEVkbmJWSnpiREJSWDJKNFQzcHNaMFpIU2tKUWNEUlFkM05JV1RKdFoyTWlMQ0o1SWpvaVdVeFVRMUpTZVhreFJrRjVSV2RFY2pCRWVsZDFjekZFYkY5UFgyWk5iR1paU25keVRYQk1TMWxSUlNKOUxDSndkWEp3YjNObGN5STZXeUpoZFhSb1pXNTBhV05oZEdsdmJpSXNJbUZ6YzJWeWRHbHZiazFsZEdodlpDSmRMQ0owZVhCbElqb2lTbk52YmxkbFlrdGxlVEl3TWpBaWZWMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFF6QklTSEIyTjB0VmJVbHlkVUZaTmtKbU1XUXROV3BXU1UxT1JIcG1lbEpUWkUwMFYwaDZiRWQxWDFFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVVJsUkhGVlUyOVZRMnAxWkZVNE9URmtZM0JoVDJaWU1VeHZhRXRVVFVwZldqUlVUbXR6VUdGWmVHUlJJaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbEVNWGszUVd0TmJIWnJNSGg1UWpoYVRrcEpRbk53TmpWR1luRjNibEpvWkZsM1pHcEVjMHhuU214NFFTSjlMQ0owZVhCbElqb2lZM0psWVhSbEluMCIsImp0aSI6InVybjp1dWlkOmYxMmEwMDYxLTY1NzctNDk5MC05ZDc4LTA3NjM5MDg3YzE5NCIsIm5iZiI6MTcwMDIxOTIyMSwic3ViIjoiZGlkOlx1MDAzY3dhbGxldF9kaWRcdTAwM2UiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhc3N1cmFuY2VfbGV2ZWwiOiJsb3ciLCJjb21wbGlhbmNlIjp7IlRCRCI6IlRCRCJ9LCJpZCI6ImRpZDpcdTAwM2N3YWxsZXRfZGlkXHUwMDNlIiwia2V5X3R5cGUiOiJcdTAwM2NUQkRcdTAwM2UiLCJ1c2VyX2F1dGhlbnRpY2F0aW9uIjoiXHUwMDNjVEJEXHUwMDNlIiwid2FsbGV0X2F1dGhlbnRpY2F0aW9uIjp7ImR0c19hdXRoX3N0cmluZzEiOiJzb21lX3ZhbHVlIiwiZHRzX2F1dGhfc3RyaW5nMiI6InNvbWVfdmFsdWUyIn0sIndhbGxldF9tZXRhZGF0YSI6eyJ3YWxsZXRfbmFtZSI6IkF3ZXNvbWUgV2FsbGV0Iiwid2FsbGV0X3ZlcnNpb24iOiIyLjAuMCJ9fSwiaWQiOiJ1cm46dXVpZDpmMTJhMDA2MS02NTc3LTQ5OTAtOWQ3OC0wNzYzOTA4N2MxOTQiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTExLTE3VDExOjA3OjAxLjgxMjc4OTAwNFoiLCJpc3N1ZXIiOiJkaWQ6aW9uOkVpQ0pIS0t4enpFNlpqSzlqQUZEaEZNbVhOUWVRcFg2RlBVcHgwY3YwbWU2eFE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSmhaR1F0Y0hWaWJHbGpMV3RsZVhNaUxDSndkV0pzYVdOTFpYbHpJanBiZXlKcFpDSTZJakJsTWpnME9XTmxMVEUwTTJVdE5HRmtNUzFpWWpRekxUVXhZekE1T0dRMk5XVTVZeUlzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSlFMVEkxTmlJc0ltdHBaQ0k2SWpCbE1qZzBPV05sTFRFME0yVXROR0ZrTVMxaVlqUXpMVFV4WXpBNU9HUTJOV1U1WXlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SWtoUE1uTm1jekJ4WkdOWWRFZG5iVkp6YkRCUlgySjRUM3BzWjBaSFNrSlFjRFJRZDNOSVdUSnRaMk1pTENKNUlqb2lXVXhVUTFKU2VYa3hSa0Y1UldkRWNqQkVlbGQxY3pGRWJGOVBYMlpOYkdaWlNuZHlUWEJNUzFsUlJTSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUlzSW1GemMyVnlkR2x2YmsxbGRHaHZaQ0pkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5WFN3aWRYQmtZWFJsUTI5dGJXbDBiV1Z1ZENJNklrVnBRekJJU0hCMk4wdFZiVWx5ZFVGWk5rSm1NV1F0TldwV1NVMU9SSHBtZWxKVFpFMDBWMGg2YkVkMVgxRWlmU3dpYzNWbVptbDRSR0YwWVNJNmV5SmtaV3gwWVVoaGMyZ2lPaUpGYVVSbFJIRlZVMjlWUTJwMVpGVTRPVEZrWTNCaFQyWllNVXh2YUV0VVRVcGZXalJVVG10elVHRlplR1JSSWl3aWNtVmpiM1psY25sRGIyMXRhWFJ0Wlc1MElqb2lSV2xFTVhrM1FXdE5iSFpyTUhoNVFqaGFUa3BKUW5Od05qVkdZbkYzYmxKb1pGbDNaR3BFYzB4blNteDRRU0o5TENKMGVYQmxJam9pWTNKbFlYUmxJbjAiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiV2FsbGV0QXR0ZXN0YXRpb25DcmVkZW50aWFsIl19fQ."
)

type sessionMetadata struct {
	challenge string
	walletDID string
}

type server struct {
	router   *mux.Router
	sessions sync.Map //sessionID -> sessionMetadata
}

func newServer() *server {
	router := mux.NewRouter()

	srv := &server{
		router: router,
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

	err = s.evaluateWalletAttestationJWT(request.SessionID, request.Proof.Jwt)
	if err != nil {
		s.writeResponse(w, http.StatusBadRequest, err.Error())

		return
	}

	response := &AttestWalletCompleteResponse{
		WalletAttestationVC: attestationVCJWT,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("failed to write response: %s", err.Error())
	}
}

func (s *server) evaluateWalletAttestationJWT(
	sessionID, attestationJWT string,
) error {
	jwtParsed, _, err := jwt.Parse(attestationJWT)
	if err != nil {
		return fmt.Errorf("parse request.Proof.Jwt: %s", err.Error())
	}

	var jwtProofClaims JwtProofClaims
	err = jwtParsed.DecodeClaims(&jwtProofClaims)
	if err != nil {
		return fmt.Errorf("decode request.Proof.Jwt: %s", err.Error())
	}

	var sessionData sessionMetadata
	sessionDataIface, ok := s.sessions.Load(sessionID)
	if ok {
		sessionData, ok = sessionDataIface.(sessionMetadata)
	}

	if !ok {
		return fmt.Errorf("session %s is unknown", sessionID)
	}

	if jwtProofClaims.Issuer != sessionData.walletDID {
		return fmt.Errorf("jwtProofClaims.Issuer is invalid, got: %s, want: %s", jwtProofClaims.Issuer, sessionData.walletDID)
	}

	if jwtProofClaims.Audience == "" {
		return fmt.Errorf("jwtProofClaims.Audience is empty")
	}

	now := time.Now()
	if now.Before(time.Unix(jwtProofClaims.IssuedAt, 0)) {
		return fmt.Errorf("jwtProofClaims.IssuedAt is invalid")
	}

	if now.After(time.Unix(jwtProofClaims.Exp, 0)) {
		return fmt.Errorf("jwtProofClaims.Exp is invalid")
	}

	if jwtProofClaims.Nonce != sessionData.challenge {
		return fmt.Errorf("jwtProofClaims.Nonce is invalid, got: %s, want: %s", jwtProofClaims.Nonce, sessionData.challenge)
	}

	return nil
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
