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

	router.HandleFunc("/issuer/policies/{policyID}/{policyVersion}/interactions/issuance", srv.evaluateIssuerIssuancePolicy).Methods(http.MethodPost)
	router.HandleFunc("/verifier/policies/{policyID}/{policyVersion}/interactions/presentation", srv.evaluateVerifierPresentationPolicy).Methods(http.MethodPost)

	return srv
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) evaluateIssuerIssuancePolicy(w http.ResponseWriter, r *http.Request) {
	var request IssuerIssuanceRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.writeResponse(
			w, http.StatusBadRequest, fmt.Sprintf("decode issuance policy request: %s", err.Error()))

		return
	}

	if request.IssuerDID == "" {
		s.writeResponse(
			w, http.StatusBadRequest, "issuer did is empty")

		return
	}

	if len(request.CredentialTypes) == 0 {
		s.writeResponse(
			w, http.StatusBadRequest, "no credential types supplied")

		return
	}

	log.Printf("handling request: %s with payload %v", r.URL.String(), request)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := &PolicyEvaluationResponse{
		Allowed: true,
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("failed to write response: %s", err.Error())
	}
}

func (s *server) evaluateVerifierPresentationPolicy(w http.ResponseWriter, r *http.Request) {
	var request VerifierPresentationRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		s.writeResponse(
			w, http.StatusBadRequest, fmt.Sprintf("decode presentation policy request: %s", err.Error()))

		return
	}

	if request.VerifierDID == "" {
		s.writeResponse(
			w, http.StatusBadRequest, "verifier did is empty")

		return
	}

	if request.CredentialMetadata == nil || len(request.CredentialMetadata) == 0 {
		s.writeResponse(
			w, http.StatusBadRequest, "no credential metadata supplied")

		return
	}

	if request.AttestationVC == nil || len(*request.AttestationVC) == 0 {
		s.writeResponse(
			w, http.StatusBadRequest, "no attestation vc supplied")

		return
	}

	log.Printf("handling request: %s with payload %v", r.URL.String(), request)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := &PolicyEvaluationResponse{
		Allowed: true,
	}

	err = json.NewEncoder(w).Encode(response)
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
