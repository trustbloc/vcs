/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"

	tlsutil "github.com/trustbloc/vcs/test/bdd/loginconsent/tls"
)

func main() {
	hydraAdminURL, err := url.Parse(os.Getenv("HYDRA_ADMIN_URL"))
	if err != nil {
		log.Fatalf("HYDRA_ADMIN_URL is missing or malformed: %s", err)

		return
	}

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

	rootCaCertsPath := os.Getenv("ROOT_CA_CERTS_PATH")
	if rootCaCertsPath == "" {
		log.Fatalf("ROOT_CA_CERTS_PATH is required")

		return
	}

	rootCACerts, err := getCertPool(false, []string{rootCaCertsPath})
	if err != nil {
		log.Fatalf("failed to init tls cert pool from path %s: %s", rootCaCertsPath, err)

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
		newServer(&config{
			hydraAdminURL: hydraAdminURL,
			tlsConfig:     &tls.Config{RootCAs: rootCACerts},
			store:         &memoryStore{m: make(map[string][]byte)},
		}),
	))
}

func getCertPool(useSystemCertPool bool, tlsCACerts []string) (*x509.CertPool, error) {
	certPool, err := tlsutil.NewCertPool(useSystemCertPool)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cert pool: %w", err)
	}

	for _, v := range tlsCACerts {
		bytes, errRead := os.ReadFile(path.Clean(v))
		if errRead != nil {
			return nil, fmt.Errorf("failed to read cert: %w", errRead)
		}

		block, _ := pem.Decode(bytes)
		if block == nil {
			return nil, fmt.Errorf("failed to decode pem")
		}

		cert, errParse := x509.ParseCertificate(block.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("failed to parse cert: %w", errParse)
		}

		certPool.Add(cert)
	}

	return certPool.Get()
}

type memoryStore struct {
	m  map[string][]byte
	mu sync.RWMutex
}

func (s *memoryStore) Get(k string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v, ok := s.m[k]
	if !ok {
		return nil, fmt.Errorf("key %s not found", k)
	}

	return v, nil
}

func (s *memoryStore) Put(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.m[k] = v

	return nil
}
