/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vcs/pkg/doc/vc"

	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
)

const (
	defaultRepresentation = "jws"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"

	issuerProfiles   = "/issuer/profiles"
	credentialStatus = "/credentials/status"
)

type crypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

type vcStore interface {
	Get(profileName, vcID string) ([]byte, error)
}

type cslStore interface {
	Upsert(cslWrapper *CSLWrapper) error
	Get(id string) (*CSLWrapper, error)
	CreateLatestListID(id int) error
	UpdateLatestListID(id int) error
	GetLatestListID() (int, error)
}

// CSLWrapper contains CSL and metadata.
type CSLWrapper struct {
	VCByte              json.RawMessage        `json:"vc"`
	Size                int                    `json:"size"`
	RevocationListIndex int                    `json:"revocationListIndex"`
	ListID              int                    `json:"listID"`
	VC                  *verifiable.Credential `json:"-"`
}

type StatusID struct {
	Context  string
	VCStatus *verifiable.TypedID
}

type Service struct {
	cslStore       cslStore
	vcStore        vcStore
	listSize       int
	crypto         crypto
	documentLoader ld.DocumentLoader
}

// New returns new Credential Status List.
func New(cslStore cslStore, vcStore vcStore, listSize int, c crypto,
	loader ld.DocumentLoader) *Service {
	return &Service{cslStore: cslStore, vcStore: vcStore, listSize: listSize, crypto: c, documentLoader: loader}
}

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

	return s.UpdateVC(credential, signer, statusValue)
}

// UpdateVC updates vc.
// nolint: gocyclo, funlen
func (s *Service) UpdateVC(v *verifiable.Credential,
	profile *vc.Signer, status bool) error {
	vcStatusProcessor, err := GetVCStatusProcessor(profile.VCStatusListVersion)
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

	bitString, err := utils.DecodeBits(cs[0].CustomFields["encodedList"].(string))
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

// CreateStatusID creates status ID.
func (s *Service) CreateStatusID(profile *vc.Signer,
	url string) (*StatusID, error) {
	vcStatusProcessor, err := GetVCStatusProcessor(profile.VCStatusListVersion)
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

	return &StatusID{
		VCStatus: vcStatusProcessor.CreateVCStatus(statusListIndex, cslWrapper.VC.ID),
		Context:  vcStatusProcessor.GetVCContext(),
	}, nil
}

func (s *Service) GetCredentialStatusURL(issuerProfileURL, issuerProfileID, statusID string) (string, error) {
	return url.JoinPath(issuerProfileURL, issuerProfiles, issuerProfileID, credentialStatus, statusID)
}

func (s *Service) GetRevocationListVC(id string) (*verifiable.Credential, error) {
	cslWrapper, err := s.getCSLWrapper(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get revocationListVC from store: %w", err)
	}

	return cslWrapper.VC, nil
}

func (s *Service) getCSLWrapper(id string) (*CSLWrapper, error) {
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

//nolint:gocognit
func (s *Service) getLatestCSLWrapper(profile *vc.Signer,
	url string, processor VcStatusProcessor) (*CSLWrapper, error) {
	// get latest id
	id, err := s.cslStore.GetLatestListID()
	if err != nil { //nolint: nestif
		if errors.Is(err, ErrDataNotFound) {
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

			return &CSLWrapper{VCByte: vcBytes, ListID: 1, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	vcID := url + "/" + strconv.Itoa(id)

	w, err := s.getCSLWrapper(vcID)
	if err != nil { //nolint: nestif
		if errors.Is(err, ErrDataNotFound) {
			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(vcID, profile, processor)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &CSLWrapper{VCByte: vcBytes, ListID: id, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	return w, nil
}

// createVC signs the VC returned from VcStatusProcessor.CreateVC.
func (s *Service) createVC(vcID string,
	profile *vc.Signer, processor VcStatusProcessor) (*verifiable.Credential, error) {
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
