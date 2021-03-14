/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
	"github.com/trustbloc/edge-service/pkg/internal/common/utils"
)

const (
	vcContext = "https://www.w3.org/2018/credentials/v1"
	// Context for Revocation List 2020
	Context = "https://w3id.org/vc-revocation-list-2020/v1"
	// CredentialStatusType credential status type
	credentialStatusStore = "credentialstatus"
	latestListID          = "latestListID"
	defaultRepresentation = "jws"

	vcType                   = "VerifiableCredential"
	revocationList2020VCType = "RevocationList2020Credential"
	revocationList2020Type   = "RevocationList2020"
	// RevocationList2020Status for RevocationList2020 Status
	RevocationList2020Status = "RevocationList2020Status"
	// RevocationListIndex for RevocationList2020 index
	RevocationListIndex = "revocationListIndex"
	// RevocationListCredential for RevocationList2020 credential
	RevocationListCredential = "revocationListCredential"

	// proof json keys
	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignatureOfType    = "type"

	bitStringSize = 128000
)

type crypto interface {
	SignCredential(dataProfile *vcprofile.DataProfile, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

// CredentialStatusManager implement spec https://w3c-ccg.github.io/vc-status-rl-2020/
type CredentialStatusManager struct {
	store    ariesstorage.Store
	url      string
	listSize int
	crypto   crypto
}

// cslWrapper contain csl and metadata
type cslWrapper struct {
	VCByte              json.RawMessage        `json:"vc"`
	Size                int                    `json:"size"`
	RevocationListIndex int                    `json:"revocationListIndex"`
	ListID              string                 `json:"listID"`
	VC                  *verifiable.Credential `json:"-"`
}

type credentialSubject struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	EncodedList string `json:"encodedList"`
}

// New returns new Credential Status List
func New(provider ariesstorage.Provider, url string, listSize int, c crypto) (*CredentialStatusManager, error) {
	store, err := provider.OpenStore(credentialStatusStore)
	if err != nil {
		return nil, err
	}

	return &CredentialStatusManager{store: store, url: url, listSize: listSize, crypto: c}, nil
}

// CreateStatusID create status id
func (c *CredentialStatusManager) CreateStatusID(profile *vcprofile.DataProfile,
	issuerSigningOpts []vccrypto.SigningOpts) (*verifiable.TypedID, error) {
	cslWrapper, err := c.getLatestCSL(profile, issuerSigningOpts)
	if err != nil {
		return nil, err
	}

	revocationListIndex := strconv.FormatInt(int64(cslWrapper.RevocationListIndex), 10)

	cslWrapper.Size++
	cslWrapper.RevocationListIndex++

	if err := c.storeCSL(cslWrapper); err != nil {
		return nil, err
	}

	if cslWrapper.Size == c.listSize {
		id, err := strconv.Atoi(cslWrapper.ListID)
		if err != nil {
			return nil, err
		}

		id++

		if err := c.store.Put(latestListID, []byte(strconv.FormatInt(int64(id), 10))); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	return &verifiable.TypedID{
		ID:   cslWrapper.VC.ID + "#" + revocationListIndex,
		Type: RevocationList2020Status, CustomFields: verifiable.CustomFields{
			RevocationListIndex:      revocationListIndex,
			RevocationListCredential: cslWrapper.VC.ID,
		},
	}, nil
}

// UpdateVC update vc
//nolint: gocyclo, funlen
func (c *CredentialStatusManager) UpdateVC(v *verifiable.Credential,
	profile *vcprofile.DataProfile, status bool) error {
	// validate vc status
	if err := c.validateVCStatus(v.Status); err != nil {
		return err
	}

	revocationListCredential, ok := v.Status.CustomFields[RevocationListCredential].(string)
	if !ok {
		return fmt.Errorf("failed to cast status revocationListCredential")
	}

	cslWrapper, err := c.getCSLWrapper(revocationListCredential)
	if err != nil {
		return err
	}

	signOpts, err := prepareSigningOpts(profile, cslWrapper.VC.Proofs, []vccrypto.SigningOpts{})
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

	revocationListIndex, err := strconv.Atoi(v.Status.CustomFields[RevocationListIndex].(string))
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

	signedCredential, err := c.crypto.SignCredential(profile, cslWrapper.VC, signOpts...)
	if err != nil {
		return err
	}

	signedCredentialBytes, err := signedCredential.MarshalJSON()
	if err != nil {
		return err
	}

	cslWrapper.VCByte = signedCredentialBytes

	return c.storeCSL(cslWrapper)
}

func (c *CredentialStatusManager) validateVCStatus(vcStatus *verifiable.TypedID) error {
	if vcStatus == nil {
		return fmt.Errorf("vc status not exist")
	}

	if vcStatus.Type != RevocationList2020Status {
		return fmt.Errorf("vc status %s not supported", vcStatus.Type)
	}

	if vcStatus.CustomFields[RevocationListIndex] == nil {
		return fmt.Errorf("revocationListIndex field not exist in vc status")
	}

	if vcStatus.CustomFields[RevocationListCredential] == nil {
		return fmt.Errorf("revocationListCredential field not exist in vc status")
	}

	return nil
}

// GetRevocationListVC get revocation list vc
func (c *CredentialStatusManager) GetRevocationListVC(id string) ([]byte, error) {
	cslWrapper, err := c.getCSLWrapper(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get revocationListVC from store: %w", err)
	}

	return cslWrapper.VCByte, nil
}

func (c *CredentialStatusManager) getCSLWrapper(id string) (*cslWrapper, error) {
	cslWrapperBytes, err := c.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	var w cslWrapper
	if errUnmarshal := json.Unmarshal(cslWrapperBytes, &w); errUnmarshal != nil {
		return nil, fmt.Errorf("failed to unmarshal csl bytes: %w", errUnmarshal)
	}

	w.VC, err = verifiable.ParseCredential(w.VCByte, verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, err
	}

	return &w, nil
}

func (c *CredentialStatusManager) getLatestCSL(profile *vcprofile.DataProfile, issuerSigningOpts []vccrypto.SigningOpts) (*cslWrapper, error) {
	// get latest id
	id, err := c.store.Get(latestListID)
	if err != nil { //nolint: nestif
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			if errPut := c.store.Put(latestListID, []byte("1")); errPut != nil {
				return nil, fmt.Errorf("failed to store latest list ID in store: %w", errPut)
			}

			// create verifiable credential that encapsulates the revocation list
			vc, errCreateVC := c.createVC(c.url+"/1", profile, issuerSigningOpts)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := vc.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &cslWrapper{vcBytes, 0, 0, "1", vc}, nil
		}

		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	vcID := c.url + "/" + string(id)

	w, err := c.getCSLWrapper(vcID)
	if err != nil { //nolint: nestif
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			// create verifiable credential that encapsulates the revocation list
			vc, errCreateVC := c.createVC(vcID, profile, issuerSigningOpts)
			if errCreateVC != nil {
				return nil, errCreateVC
			}

			vcBytes, errMarshal := vc.MarshalJSON()
			if errMarshal != nil {
				return nil, errMarshal
			}

			return &cslWrapper{vcBytes, 0, 0, string(id), vc}, nil
		}

		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	return w, nil
}

func (c *CredentialStatusManager) createVC(vcID string,
	profile *vcprofile.DataProfile, issuerSigningOpts []vccrypto.SigningOpts) (*verifiable.Credential, error) {
	credential := &verifiable.Credential{}
	credential.Context = []string{vcContext, Context}
	credential.ID = vcID
	credential.Types = []string{vcType, revocationList2020VCType}
	credential.Issuer = verifiable.Issuer{ID: profile.DID}
	credential.Issued = util.NewTime(time.Now().UTC())

	size := c.listSize

	if size < bitStringSize {
		size = bitStringSize
	}

	encodeBits, err := utils.NewBitString(size).EncodeBits()
	if err != nil {
		return nil, err
	}

	credential.Subject = &credentialSubject{
		ID: credential.ID + "#list", Type: revocationList2020Type,
		EncodedList: encodeBits,
	}

	signOpts, err := prepareSigningOpts(profile, credential.Proofs, issuerSigningOpts)
	if err != nil {
		return nil, err
	}

	signedCredential, err := c.crypto.SignCredential(profile, credential, signOpts...)
	if err != nil {
		return nil, err
	}

	return signedCredential, nil
}

func (c *CredentialStatusManager) storeCSL(cslWrapper *cslWrapper) error {
	cslWrapperBytes, err := json.Marshal(cslWrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal csl struct: %w", err)
	}

	if err := c.store.Put(cslWrapper.VC.ID, cslWrapperBytes); err != nil {
		return fmt.Errorf("failed to store csl in store: %w", err)
	}

	return nil
}

// prepareSigningOpts prepares signing opts from recently issued proof of given credential
func prepareSigningOpts(profile *vcprofile.DataProfile, proofs []verifiable.Proof,
	issuerSigningOpts []vccrypto.SigningOpts) ([]vccrypto.SigningOpts, error) {
	var signingOpts []vccrypto.SigningOpts

	if len(proofs) == 0 {
		return issuerSigningOpts, nil
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
	if vm != profile.Creator {
		signingOpts = append(signingOpts, vccrypto.WithVerificationMethod(vm))
	}

	signType, err := getStringValue(jsonKeySignatureOfType, proof)
	if err != nil {
		return nil, err
	}

	signingOpts = append(signingOpts, vccrypto.WithSignatureType(signType))

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
