/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vcs/pkg/doc/vc"

	"github.com/trustbloc/vcs/pkg/doc/vc/bitstring"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/service/issuecredential"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/cslstore"
)

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"

	issuerProfiles   = "/issuer/profiles"
	credentialStatus = "/credentials/status"

	cslRequestTokenName = "csl"
)

var logger = log.New("vcs-statuslist-service")

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type crypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type vcStore interface {
	Get(profileName, vcID string) ([]byte, error)
}

type cslStore interface {
	Upsert(cslWrapper *cslstore.CSLWrapper) error
	Get(id string) (*cslstore.CSLWrapper, error)
	CreateLatestListID(id int) error
	UpdateLatestListID(id int) error
	GetLatestListID() (int, error)
}

type Config struct {
	VDR            vdrapi.Registry
	TLSConfig      *tls.Config
	RequestTokens  map[string]string
	DocumentLoader ld.DocumentLoader
	CSLStore       cslStore
	VCStore        vcStore
	ListSize       int
	Crypto         crypto
}

type Service struct {
	httpClient     httpClient
	requestTokens  map[string]string
	vdr            vdrapi.Registry
	cslStore       cslStore
	vcStore        vcStore
	listSize       int
	crypto         crypto
	documentLoader ld.DocumentLoader
}

// New returns new Credential Status service.
func New(config *Config) *Service {
	return &Service{
		httpClient:     &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:  config.RequestTokens,
		vdr:            config.VDR,
		cslStore:       config.CSLStore,
		vcStore:        config.VCStore,
		listSize:       config.ListSize,
		crypto:         config.Crypto,
		documentLoader: config.DocumentLoader,
	}
}

// UpdateVCStatus fetches credential based on credentialID and updates StatusListCredential associated with it.
func (s *Service) UpdateVCStatus(signer *vc.Signer, profileName, credentialID, status string) error {
	vcBytes, err := s.vcStore.Get(profileName, credentialID)
	if err != nil {
		return err
	}

	credential, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return err
	}

	statusValue, err := strconv.ParseBool(status)
	if err != nil {
		return err
	}

	return s.updateVC(credential, signer, statusValue)
}

// CreateStatusID creates issuecredential.StatusID.
func (s *Service) CreateStatusID(profile *vc.Signer,
	url string) (*issuecredential.StatusID, error) {
	vcStatusProcessor, err := GetVCStatusProcessor(profile.VCStatusListType)
	if err != nil {
		return nil, err
	}

	cslWrapper, err := s.getLatestCSLWrapper(profile, url, vcStatusProcessor)
	if err != nil {
		return nil, err
	}

	statusListIndex := strconv.FormatInt(int64(cslWrapper.RevocationListIndex), 10)

	cslWrapper.Size++
	cslWrapper.RevocationListIndex++

	if err = s.cslStore.Upsert(cslWrapper); err != nil {
		return nil, fmt.Errorf("failed to store csl in store: %w", err)
	}

	if cslWrapper.Size == s.listSize {
		id := cslWrapper.ListID

		id++

		if err = s.cslStore.UpdateLatestListID(id); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	return &issuecredential.StatusID{
		VCStatus: vcStatusProcessor.CreateVCStatus(statusListIndex, cslWrapper.VC.ID),
		Context:  vcStatusProcessor.GetVCContext(),
	}, nil
}

// GetStatusListVCURL returns StatusListVC URL.
func (s *Service) GetStatusListVCURL(issuerProfileURL, issuerProfileID, statusID string) (string, error) {
	return url.JoinPath(issuerProfileURL, issuerProfiles, issuerProfileID, credentialStatus, statusID)
}

// GetStatusListVC returns StatusListVC from underlying cslStore.
// Used for handling public HTTP requests.
func (s *Service) GetStatusListVC(id string) (*verifiable.Credential, error) {
	cslWrapper, err := s.getCSLWrapper(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get revocationListVC from store: %w", err)
	}

	return cslWrapper.VC, nil
}

// Resolve resolves statusListVCURI and returns StatusListVC.
// Used for credential verification.
// statusListVCURI might be either HTTP URL or DID URL.
func (s *Service) Resolve(statusListVCURI string) (*verifiable.Credential, error) {
	var vcBytes []byte
	var err error
	switch {
	case strings.HasPrefix(statusListVCURI, "did:"):
		vcBytes, err = s.resolveDIDRelativeURL(statusListVCURI)
	default:
		vcBytes, err = s.resolveHTTPUrl(statusListVCURI)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to resolve statusListVCURI: %w", err)
	}

	statusListVC, err := s.parseAndVerifyVC(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	return statusListVC, nil
}

func (s *Service) resolveHTTPUrl(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.sendHTTPRequest(req, http.StatusOK, s.requestTokens[cslRequestTokenName])
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Service) parseAndVerifyVC(vcBytes []byte) (*verifiable.Credential, error) {
	return verifiable.ParseCredential(
		vcBytes,
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(s.vdr).PublicKeyFetcher(),
		),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader),
	)
}

func (s *Service) getCSLWrapper(id string) (*cslstore.CSLWrapper, error) {
	cslWrapper, err := s.cslStore.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	cslWrapper.VC, err = verifiable.ParseCredential(cslWrapper.VCByte, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, err
	}

	return cslWrapper, nil
}

func (s *Service) sendHTTPRequest(req *http.Request, status int, token string) ([]byte, error) {
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warn("failed to close response body")
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("Unable to read response", log.WithHTTPStatus(resp.StatusCode), log.WithError(err))
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("failed to read response body for status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

//nolint:gocognit
func (s *Service) getLatestCSLWrapper(profile *vc.Signer,
	url string, processor vc.StatusProcessor) (*cslstore.CSLWrapper, error) {
	// get latest id
	id, err := s.cslStore.GetLatestListID()
	if err != nil { //nolint: nestif
		if errors.Is(err, cslstore.ErrDataNotFound) {
			if errPut := s.cslStore.CreateLatestListID(1); errPut != nil {
				return nil, fmt.Errorf("failed to store latest list ID in store: %w", errPut)
			}

			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(url+"/1", profile, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &cslstore.CSLWrapper{VCByte: vcBytes, ListID: 1, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	vcID := url + "/" + strconv.Itoa(id)

	w, err := s.getCSLWrapper(vcID)
	if err != nil { //nolint: nestif
		if errors.Is(err, cslstore.ErrDataNotFound) {
			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(vcID, profile, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &cslstore.CSLWrapper{VCByte: vcBytes, ListID: id, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	return w, nil
}

// createVC signs the VC returned from VcStatusProcessor.CreateVC.
func (s *Service) createVC(vcID string,
	profile *vc.Signer, processor vc.StatusProcessor) (*verifiable.Credential, error) {
	credential, err := processor.CreateVC(vcID, s.listSize, profile)
	if err != nil {
		return nil, err
	}

	signOpts, err := prepareSigningOpts(profile, credential.Proofs)
	if err != nil {
		return nil, err
	}

	return s.crypto.SignCredential(profile, credential, signOpts...)
}

// prepareSigningOpts prepares signing opts from recently issued proof of given credential.
func prepareSigningOpts(profile *vc.Signer, proofs []verifiable.Proof) ([]vccrypto.SigningOpts, error) {
	var signingOpts []vccrypto.SigningOpts

	if len(proofs) == 0 {
		return signingOpts, nil
	}

	// pick latest proof if there are multiple
	proof := proofs[len(proofs)-1]

	representation := defaultRepresentation
	if _, ok := proof[jsonKeyProofValue]; ok {
		representation = jsonKeyProofValue
	}

	signingOpts = append(signingOpts, vccrypto.WithSigningRepresentation(representation))

	purpose, err := getStringValue(jsonKeyProofPurpose, proof)
	if err != nil {
		return nil, err
	}

	signingOpts = append(signingOpts, vccrypto.WithPurpose(purpose))

	vm, err := getStringValue(jsonKeyVerificationMethod, proof)
	if err != nil {
		return nil, err
	}

	// add verification method option only when it is not matching profile creator
	if !strings.HasPrefix(profile.Creator, "did:key") && vm != profile.Creator {
		signingOpts = append(signingOpts, vccrypto.WithVerificationMethod(vm))
	}

	signTypeName, err := getStringValue(jsonKeySignatureOfType, proof)
	if err != nil {
		return nil, err
	}

	if signTypeName != "" {
		signType, err := vcsverifiable.GetSignatureTypeByName(signTypeName)
		if err != nil {
			return nil, err
		}

		signingOpts = append(signingOpts, vccrypto.WithSignatureType(signType))
	}

	return signingOpts, nil
}

func getStringValue(key string, vMap map[string]interface{}) (string, error) {
	if val, ok := vMap[key]; ok {
		if s, ok := val.(string); ok {
			return s, nil
		}

		return "", fmt.Errorf("invalid '%s' type", key)
	}

	return "", nil
}

// updateVC updates StatusListCredential associated with v.
// nolint: gocyclo, funlen
func (s *Service) updateVC(v *verifiable.Credential,
	profile *vc.Signer, status bool) error {
	vcStatusProcessor, err := GetVCStatusProcessor(profile.VCStatusListType)
	if err != nil {
		return err
	}
	// validate vc status
	if err = vcStatusProcessor.ValidateStatus(v.Status); err != nil {
		return err
	}

	statusListVCID, err := vcStatusProcessor.GetStatusVCURI(v.Status)
	if err != nil {
		return err
	}

	cslWrapper, err := s.getCSLWrapper(statusListVCID)
	if err != nil {
		return err
	}

	signOpts, err := prepareSigningOpts(profile, cslWrapper.VC.Proofs)
	if err != nil {
		return err
	}

	cs, ok := cslWrapper.VC.Subject.([]verifiable.Subject)
	if !ok {
		return fmt.Errorf("failed to cast vc subject")
	}

	bitString, err := bitstring.DecodeBits(cs[0].CustomFields["encodedList"].(string))
	if err != nil {
		return err
	}

	revocationListIndex, err := vcStatusProcessor.GetStatusListIndex(v.Status)
	if err != nil {
		return err
	}

	if errSet := bitString.Set(revocationListIndex, status); errSet != nil {
		return errSet
	}

	cs[0].CustomFields["encodedList"], err = bitString.EncodeBits()
	if err != nil {
		return err
	}

	// remove all proofs because we are updating VC
	cslWrapper.VC.Proofs = nil

	signedCredential, err := s.crypto.SignCredential(profile, cslWrapper.VC, signOpts...)
	if err != nil {
		return err
	}

	signedCredentialBytes, err := signedCredential.MarshalJSON()
	if err != nil {
		return err
	}

	cslWrapper.VCByte = signedCredentialBytes

	return s.cslStore.Upsert(cslWrapper)
}
