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

	"github.com/gorilla/mux"
)

type server struct {
	router *mux.Router
}

func newServer() *server {
	router := mux.NewRouter()

	srv := &server{
		router: router,
	}

	router.HandleFunc("/wallet/interactions/presentation", srv.evaluateWalletPresentation).Methods(http.MethodPost)
	router.HandleFunc("/verifier/policies/policyID/policyVersion/interactions/presentation", srv.evaluateVerifierPresentation).Methods(http.MethodPost)

	return srv
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) evaluateVerifierPresentation(w http.ResponseWriter, r *http.Request) {
	var request VerifierPresentationValidationConfig

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.writeResponse(
			w, http.StatusBadRequest, fmt.Sprintf("failed to decode evaluate request: %s", err.Error()))

		return
	}

	if len(request.AttestationVC) < 1 {
		s.writeResponse(
			w, http.StatusBadRequest, "at least one attestation vc should be supplied")

		return
	}

	if len(request.RequestedVCMetadata) < 1 {
		s.writeResponse(
			w, http.StatusBadRequest, "at least one requested vc metadata should be supplied")

		return
	}

	log.Printf("handling request: %s with payload %v", r.URL.String(), request)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	claims := map[string]interface{}{
		"allowed": true,
	}

	err = json.NewEncoder(w).Encode(claims)
	if err != nil {
		log.Printf("failed to write response: %s", err.Error())
	}
}

func (s *server) evaluateWalletPresentation(w http.ResponseWriter, r *http.Request) {
	var request WalletPresentationValidationConfig

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.writeResponse(
			w, http.StatusBadRequest, fmt.Sprintf("failed to decode evaluate request: %s", err.Error()))

		return
	}

	if len(request.VerifierDID) < 1 {
		s.writeResponse(
			w, http.StatusBadRequest, "verifier did is not supplied")

		return
	}

	if len(request.RequestedVCMetadata) < 1 {
		s.writeResponse(
			w, http.StatusBadRequest, "at least one requested vc metadata should be supplied")

		return
	}

	log.Printf("handling request: %s with payload %v", r.URL.String(), request)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	claims := map[string]interface{}{
		"allowed": true,
	}

	err = json.NewEncoder(w).Encode(claims)
	if err != nil {
		log.Printf("failed to write response: %s", err.Error())
	}
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
