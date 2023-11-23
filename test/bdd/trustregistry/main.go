/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	serveCertPath := os.Getenv("TLS_CERT_PATH")
	if serveCertPath == "" {
		log.Fatalf("TLS_CERT_PATH is required")

		return
	}

	serveKeyPath := os.Getenv("TLS_KEY_PATH")
	if serveKeyPath == "" {
		log.Fatalf("TLS_KEY_PATH is required")

		return
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		log.Fatalf("LISTEN_ADDR is required")

		return
	}

	log.Printf("Listening on %s", listenAddr)

	log.Fatal(http.ListenAndServeTLS(
		listenAddr,
		serveCertPath, serveKeyPath,
		newServer(),
	))
}
