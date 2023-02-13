/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4ci

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	vdrpkg "github.com/hyperledger/aries-framework-go/pkg/vdr"
	"golang.org/x/oauth2"

	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	"github.com/trustbloc/vcs/pkg/doc/verifiable"
)

func getCredential(
	oauthClient *oauth2.Config,
	token *oauth2.Token,
	tlsConfig *tls.Config,
	debug bool,
) (*credentialResponse, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	diddoc, err := createDID(tlsConfig, publicKey)
	if err != nil {
		return nil, fmt.Errorf("create did: %w", err)
	}

	jws, err := createProof(
		oauthClient.ClientID,
		token.Extra("c_nonce").(string),
		privateKey,
		diddoc.VerificationMethod[0].ID,
	)
	if err != nil {
		return nil, fmt.Errorf("create proof: %w", err)
	}

	b, err := json.Marshal(credentialRequest{
		Format: string(verifiable.JwtVCJson),
		Type:   "UniversityDegreeCredential",
		Proof: jwtProof{
			ProofType: "jwt",
			JWT:       jws,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}

	var transport http.RoundTripper = &http.Transport{TLSClientConfig: tlsConfig}

	if debug {
		transport = &DumpTransport{transport}
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: transport})

	httpClient := oauthClient.Client(ctx, token)

	resp, err := httpClient.Post(vcsCredentialEndpoint, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get credential: %w", parseError(resp.Body))
	}

	var credentialResp credentialResponse

	if err = json.NewDecoder(resp.Body).Decode(&credentialResp); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}

	return &credentialResp, nil
}

type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (r *responseError) Error() string {
	return r.Message
}

func parseError(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var errResp responseError

	if err = json.Unmarshal(b, &errResp); err != nil {
		return errors.New(string(b))
	}

	return &errResp
}

func createDID(
	tlsConfig *tls.Config,
	pub ed25519.PublicKey,
) (*docdid.Doc, error) {
	vdr, err := orb.New(nil, orb.WithDomain(didDomain), orb.WithTLSConfig(tlsConfig),
		orb.WithAuthToken(didServiceAuthToken))
	if err != nil {
		return nil, fmt.Errorf("create orb vdr: %w", err)
	}

	jwk, err := jwksupport.JWKFromKey(pub)
	if err != nil {
		return nil, fmt.Errorf("create jwk from key: %w", err)
	}

	docID := uuid.NewString()
	keyID := uuid.NewString()

	vm, err := docdid.NewVerificationMethodFromJWK(docID+"#"+keyID, vccrypto.JSONWebKey2020, "", jwk)
	if err != nil {
		return nil, fmt.Errorf("create verification method: %w", err)
	}

	doc := &docdid.Doc{
		ID:              docID,
		Authentication:  []docdid.Verification{*docdid.NewReferencedVerification(vm, docdid.Authentication)},
		AssertionMethod: []docdid.Verification{*docdid.NewReferencedVerification(vm, docdid.AssertionMethod)},
	}

	vdrRegistry := vdrpkg.New(vdrpkg.WithVDR(vdr))

	updateKey, _, err := ed25519.GenerateKey(rand.Reader)
	recoverKey, _, err := ed25519.GenerateKey(rand.Reader)

	docResolution, err := vdrRegistry.Create(
		orb.DIDMethod,
		doc,
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoverKey),
	)
	if err != nil {
		return nil, fmt.Errorf("register did in vdr: %w", err)
	}

	return docResolution.DIDDocument, nil
}

func createProof(
	oauthClientId string,
	cNonce string,
	privateKey ed25519.PrivateKey,
	verificationKID string,
) (string, error) {
	jwtSigner := jwt.NewEd25519Signer(privateKey)

	claims := &jwtProofClaims{
		Issuer:   oauthClientId,
		IssuedAt: time.Now().Unix(),
		Nonce:    cNonce,
	}

	jwtHeaders := map[string]interface{}{
		"alg": "EdDSA",
		"kid": verificationKID,
	}

	signedJWT, err := jwt.NewSigned(claims, jwtHeaders, jwtSigner)
	if err != nil {
		return "", fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serialize signed jwt: %w", err)
	}

	return jws, nil
}
