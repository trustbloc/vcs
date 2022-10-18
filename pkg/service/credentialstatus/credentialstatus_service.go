/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"

	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
)

const (
	vcContext                  = "https://www.w3.org/2018/credentials/v1"
	jsonWebSignature2020Ctx    = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
	bbsBlsSignature2020Context = "https://w3id.org/security/bbs/v1"
	// Context for Revocation List 2021.
	Context = "https://w3id.org/vc/status-list/2021/v1"
	// CredentialStatusType credential status type.
	defaultRepresentation = "jws"

	vcType                   = "VerifiableCredential"
	revocationList2021VCType = "StatusList2021Credential"
	revocationList2021Type   = "StatusList2021"

	// StatusListIndex for RevocationList2021.
	StatusListIndex = "statusListIndex"
	// StatusListCredential for RevocationList2021.
	StatusListCredential = "statusListCredential"
	// StatusPurpose for RevocationList2021.
	StatusPurpose = "statusPurpose"
	// StatusList2021Entry for RevocationList2021.
	StatusList2021Entry = "StatusList2021Entry"

	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"

	bitStringSize = 128000

	issuerProfiles   = "/issuer/profiles"
	credentialStatus = "/credentials/status"
)

type crypto interface {
	SignCredential(signerData *vc.Signer, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

// Service implement spec https://w3c-ccg.github.io/vc-status-rl-2020/.
type Service struct {
	cslStore       vcsstorage.CSLStore
	vcStore        vcsstorage.VCStore
	listSize       int
	crypto         crypto
	documentLoader ld.DocumentLoader
}

type credentialSubject struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	StatusPurpose string `json:"statusPurpose"`
	EncodedList   string `json:"encodedList"`
}

// New returns new Credential Status List.
func New(provider vcsstorage.Provider, listSize int, c crypto,
	loader ld.DocumentLoader) (*Service, error) {
	cslStore, err := provider.OpenCSLStore()
	if err != nil {
		return nil, err
	}

	vcStore, err := provider.OpenVCStore()
	if err != nil {
		return nil, err
	}

	return &Service{cslStore: cslStore, vcStore: vcStore, listSize: listSize, crypto: c, documentLoader: loader}, nil
}

// CreateStatusID creates status ID.
func (s *Service) CreateStatusID(profile *vc.Signer,
	url string) (*verifiable.TypedID, error) {
	cslWrapper, err := s.getLatestCSLWrapper(profile, url)
	if err != nil {
		return nil, err
	}

	revocationListIndex := strconv.FormatInt(int64(cslWrapper.RevocationListIndex), 10)

	cslWrapper.Size++
	cslWrapper.RevocationListIndex++

	if err = s.cslStore.PutCSLWrapper(cslWrapper); err != nil {
		return nil, fmt.Errorf("failed to store csl in store: %w", err)
	}

	if cslWrapper.Size == s.listSize {
		id := cslWrapper.ListID

		id++

		if err := s.cslStore.UpdateLatestListID(id); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	return &verifiable.TypedID{
		ID:   uuid.New().URN(),
		Type: StatusList2021Entry,
		CustomFields: verifiable.CustomFields{
			StatusPurpose:        "revocation",
			StatusListIndex:      revocationListIndex,
			StatusListCredential: cslWrapper.VC.ID,
		},
	}, nil
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
	// validate vc status
	if err := s.validateVCStatus(v.Status); err != nil {
		return err
	}

	revocationListCredential, ok := v.Status.CustomFields[StatusListCredential].(string)
	if !ok {
		return fmt.Errorf("failed to cast status statusListCredential")
	}

	cslWrapper, err := s.getCSLWrapper(revocationListCredential)
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

	revocationListIndex, err := strconv.Atoi(v.Status.CustomFields[StatusListIndex].(string))
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

	return s.cslStore.PutCSLWrapper(cslWrapper)
}

func (s *Service) GetCredentialStatusURL(issuerProfileURL, issuerProfileID, statusID string) (string, error) {
	return url.JoinPath(issuerProfileURL, issuerProfiles, issuerProfileID, credentialStatus, statusID)
}

func (s *Service) validateVCStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != StatusList2021Entry {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[StatusListIndex] == nil {
		return fmt.Errorf("statusListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[StatusListCredential] == nil {
		return fmt.Errorf("statusListCredential field not exist in vc status")
	}

	if vcStatus.CustomFields[StatusPurpose] == nil {
		return fmt.Errorf("statusPurpose field not exist in vc status")
	}

	return nil
}

func (s *Service) GetRevocationListVC(id string) (*verifiable.Credential, error) {
	cslWrapper, err := s.getCSLWrapper(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get revocationListVC from store: %w", err)
	}

	return cslWrapper.VC, nil
}

func (s *Service) getCSLWrapper(id string) (*vcsstorage.CSLWrapper, error) {
	cslWrapper, err := s.cslStore.GetCSLWrapper(id)
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
	url string) (*vcsstorage.CSLWrapper, error) {
	// get latest id
	id, err := s.cslStore.GetLatestListID()
	if err != nil { //nolint: nestif
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			if errPut := s.cslStore.UpdateLatestListID(1); errPut != nil {
				return nil, fmt.Errorf("failed to store latest list ID in store: %w", errPut)
			}

			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(url+"/1", profile)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &vcsstorage.CSLWrapper{VCByte: vcBytes, ListID: 1, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	vcID := url + "/" + strconv.Itoa(id)

	w, err := s.getCSLWrapper(vcID)
	if err != nil { //nolint: nestif
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			// create verifiable credential that encapsulates the revocation list
			credentials, errCreateVC := s.createVC(vcID, profile)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := credentials.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &vcsstorage.CSLWrapper{VCByte: vcBytes, ListID: id, VC: credentials}, nil
		}

		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	return w, nil
}

func (s *Service) createVC(vcID string,
	profile *vc.Signer) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	credential.Context = []string{vcContext, Context}

	if profile.SignatureType == vcsverifiable.JSONWebSignature2020 {
		credential.Context = append(credential.Context, jsonWebSignature2020Ctx)
	}

	if profile.SignatureType == vcsverifiable.BbsBlsSignature2020 {
		credential.Context = append(credential.Context, bbsBlsSignature2020Context)
	}

	credential.ID = vcID
	credential.Types = []string{vcType, revocationList2021VCType}
	credential.Issuer = verifiable.Issuer{ID: profile.DID}
	credential.Issued = util.NewTime(time.Now().UTC())

	size := s.listSize

	if size < bitStringSize {
		size = bitStringSize
	}

	encodeBits, err := utils.NewBitString(size).EncodeBits()
	if err != nil {
		return nil, err
	}

	credential.Subject = &credentialSubject{
		ID:            credential.ID + "#list",
		Type:          revocationList2021Type,
		StatusPurpose: "revocation",
		EncodedList:   encodeBits,
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
