/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type server struct {
	router *mux.Router
}

func newServer() *server {
	router := mux.NewRouter()

	srv := &server{
		router: router,
	}

	router.HandleFunc("/policies/evaluate", srv.evaluatePolicies).Methods(http.MethodPost)

	return srv
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) evaluatePolicies(w http.ResponseWriter, r *http.Request) {
	var request map[string]interface{}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Printf("failed to decode evaluate request: %s", err.Error())

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
