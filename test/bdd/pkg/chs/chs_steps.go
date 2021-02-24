/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package chs

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/cucumber/godog"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edge-service/pkg/client/csh/models"
	bddctx "github.com/trustbloc/edge-service/test/bdd/pkg/context"
)

const (
	cshHost           = "localhost:8095"
	kmsBaseURL        = "https://localhost:8077"
	kmsNetworkBaseURL = "https://kms.example.com:8077"
	edvBaseURL        = "http://localhost:8071/encrypted-data-vaults"
	edvNetworkBaseURL = "http://edv.rest.example.com:8071/encrypted-data-vaults"
)

// NewSteps returns BDD test steps for the confidential storage hub.
func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		ctx:  ctx,
		docs: make([]*docCoords, 0),
		refs: make([]string, 0),
	}
}

type docCoords struct {
	vaultID string
	docID   string
	path    string
	edvZCAP string
	kmsZCAP string
}

// Steps BDD test steps for the confidential storage hub.
type Steps struct {
	ctx              *bddctx.BDDContext
	user             *user
	docs             []*docCoords
	refs             []string
	comparisonResult bool
}

// RegisterSteps for this BDD test.
func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step("^the user requests a new confidential-storage-hub profile$", s.userCreatesProfile)
	gs.Step("^the confidential-storage-hub profile is created$", s.userProfileIsCreated)
	gs.Step(`^the user has a profile$`, s.userHasProfile)
	gs.Step(`^the user saves a Confidential Storage document with content "([^"]*)"$`, s.userSavesDocument)
	gs.Step(`^the user creates a RefQuery for one document$`, s.userCreatesRefQuery)
	gs.Step(`^the user authorizes the CSH to read the documents$`, s.userAuthorizesCSHToReadDocuments)
	gs.Step(`^the user requests a comparison between the two documents$`, s.userRequestsComparison)
	gs.Step(`^the result is "([^"]*)"$`, s.confirmComparisonResult)
}

func (s *Steps) userCreatesProfile() error {
	var err error

	s.user, err = newUser(cshHost, edvBaseURL, kmsBaseURL, s.ctx.TLSConfig)
	if err != nil {
		return fmt.Errorf("failed to create new user: %w", err)
	}

	err = s.user.requestNewProfile()
	if err != nil {
		return fmt.Errorf("user failed to create a profile: %w", err)
	}

	s.docs = make([]*docCoords, 0)
	s.refs = make([]string, 0)

	return nil
}

func (s *Steps) userProfileIsCreated() error {
	if s.user.profile.ID == "" {
		return errors.New("profile does not have an ID")
	}

	if s.user.profile.Controller == nil {
		return errors.New("profile does not have a controller")
	}

	if s.user.profile.Zcap == "" {
		return errors.New("profile does not have a zcap")
	}

	zcap, err := parseZCAP(s.user.profile.Zcap)
	if err != nil {
		return fmt.Errorf("failed to parse profile zcap: %w", err)
	}

	if s.user.controller != zcap.Controller {
		return fmt.Errorf(
			"the user is not the profile's controller: user.controller=%s profile.controller=%s",
			s.user.controller, *s.user.profile.Controller,
		)
	}

	if s.user.controller != zcap.Invoker {
		return fmt.Errorf(
			"the user is not the profile's invoker: user.controller=%s profile.controller=%s",
			s.user.controller, *s.user.profile.Controller,
		)
	}

	return nil
}

func (s *Steps) userHasProfile() error {
	err := s.userCreatesProfile()
	if err != nil {
		return fmt.Errorf("failed to create new user: %w", err)
	}

	err = s.userProfileIsCreated()
	if err != nil {
		return fmt.Errorf("failed to validate new user csh profile: %w", err)
	}

	return nil
}

func (s *Steps) userSavesDocument(contents string) error {
	coords, err := s.user.saveInConfidentialStorage(contents)
	if err != nil {
		return fmt.Errorf("user failed to save document: %w", err)
	}

	s.docs = append(s.docs, coords)

	return nil
}

func (s *Steps) userCreatesRefQuery() error {
	if len(s.docs) == 0 {
		return errors.New("BDD test steps error: user has not saved any docs yet")
	}

	doc := s.docs[len(s.docs)-1]
	s.docs = s.docs[:len(s.docs)-1]

	ref, err := s.user.createRef(&models.DocQuery{
		VaultID: &doc.vaultID,
		DocID:   &doc.docID,
		Path:    doc.path,
		UpstreamAuth: &models.DocQueryAO1UpstreamAuth{
			Edv: &models.UpstreamAuthorization{
				BaseURL: edvNetworkBaseURL,
				Zcap:    doc.edvZCAP,
			},
			Kms: &models.UpstreamAuthorization{
				BaseURL: kmsNetworkBaseURL,
				Zcap:    doc.kmsZCAP,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("user failed to create ref: %w", err)
	}

	s.refs = append(s.refs, ref)

	return nil
}

func (s *Steps) userAuthorizesCSHToReadDocuments() error {
	chsZCAP, err := parseCompressedZCAP(s.user.profile.Zcap)
	if err != nil {
		return fmt.Errorf("failed to parse CHS profile zcap: %w", err)
	}

	invoker := verificationMethod(chsZCAP)

	for i := range s.docs {
		s.docs[i].edvZCAP, s.docs[i].kmsZCAP, err = s.user.authorizeRead(invoker, s.docs[i].docID)
		if err != nil {
			return fmt.Errorf("user failed to provide authorization for document1: %w", err)
		}
	}

	return nil
}

func (s *Steps) userRequestsComparison() error {
	queries := make([]models.Query, len(s.docs)+len(s.refs))

	for i := range s.docs {
		queries[i] = &models.DocQuery{
			VaultID: &s.docs[i].vaultID,
			DocID:   &s.docs[i].docID,
			Path:    s.docs[i].path,
			UpstreamAuth: &models.DocQueryAO1UpstreamAuth{
				Edv: &models.UpstreamAuthorization{
					BaseURL: edvNetworkBaseURL,
					Zcap:    s.docs[i].edvZCAP,
				},
				Kms: &models.UpstreamAuthorization{
					BaseURL: kmsNetworkBaseURL,
					Zcap:    s.docs[i].kmsZCAP,
				},
			},
		}
	}

	for i := range s.refs {
		idx := i + len(s.docs)
		queries[idx] = &models.RefQuery{
			Ref: &s.refs[i],
		}
	}

	var err error

	s.comparisonResult, err = s.user.compare(queries...)
	if err != nil {
		return fmt.Errorf("user failed to execute comparison: %w", err)
	}

	return nil
}

func (s *Steps) confirmComparisonResult(want string) error {
	expected, err := strconv.ParseBool(want)
	if err != nil {
		return fmt.Errorf("'%s' is not a bool value: %w", want, err)
	}

	if s.comparisonResult != expected {
		return fmt.Errorf("expected '%t' but got '%t'", expected, s.comparisonResult)
	}

	return nil
}

func parseZCAP(encoded string) (*zcapld.Capability, error) {
	deflated, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64URL-decode zcap: %w", err)
	}

	pump, err := gzip.NewReader(bytes.NewReader(deflated))
	if err != nil {
		return nil, fmt.Errorf("failed to init gzip reader: %w", err)
	}

	inflated := bytes.NewBuffer(nil)

	_, err = inflated.ReadFrom(pump)
	if err != nil {
		return nil, fmt.Errorf("failed to gunzip zcap: %w", err)
	}

	zcap, err := zcapld.ParseCapability(inflated.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse zcap: %w", err)
	}

	return zcap, nil
}

func parseCompressedZCAP(compressed string) (*zcapld.Capability, error) {
	uncompressed, err := base64URLDecodeThenGunzip(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress zcap: %w", err)
	}

	zcap, err := zcapld.ParseCapability(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse zcap: %w", err)
	}

	return zcap, nil
}

func gzipThenBase64URL(msg []byte) (string, error) {
	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err := w.Write(msg)
	if err != nil {
		return "", fmt.Errorf("failed to compress msg: %w", err)
	}

	err = w.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}

func base64URLDecodeThenGunzip(encoded string) ([]byte, error) {
	compressed, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url-decode string: %w", err)
	}

	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("failed to open a new gzip reader: %w", err)
	}

	inflated := bytes.NewBuffer(nil)

	_, err = inflated.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to gunzip string: %w", err)
	}

	return inflated.Bytes(), nil
}

func verificationMethod(zcap *zcapld.Capability) string {
	return zcap.Proof[0]["verificationMethod"].(string)
}

func capabilityChain(zcap *zcapld.Capability) []interface{} {
	chain, ok := zcap.Proof[0]["capabilityChain"]
	if ok {
		return chain.([]interface{})
	}

	return nil
}
