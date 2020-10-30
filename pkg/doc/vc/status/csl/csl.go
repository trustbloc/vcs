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
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/storage"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	vcprofile "github.com/trustbloc/edge-service/pkg/doc/vc/profile"
)

const (
	// Context for CredentialStatusList2017
	Context = "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
	// CredentialStatusType credential status type
	CredentialStatusType  = "CredentialStatusList2017"
	credentialStatusStore = "credentialstatus"
	latestListID          = "latestListID"
	defaultRepresentation = "jws"

	// proof json keys
	jsonKeyProofValue         = "proofValue"
	jsonKeyProofPurpose       = "proofPurpose"
	jsonKeyVerificationMethod = "verificationMethod"
	jsonKeySignaturefType     = "type"
)

type crypto interface {
	SignCredential(dataProfile *vcprofile.DataProfile, vc *verifiable.Credential,
		opts ...vccrypto.SigningOpts) (*verifiable.Credential, error)
}

// CredentialStatusManager implement spec https://w3c-ccg.github.io/vc-csl2017/
type CredentialStatusManager struct {
	store    storage.Store
	url      string
	listSize int
	crypto   crypto
}

// CSL struct
type CSL struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	VC          []string `json:"verifiableCredential"`
}

// cslWrapper contain csl and metadata
type cslWrapper struct {
	CSL  *CSL   `json:"csl"`
	Size int    `json:"size"`
	ID   string `json:"id"`
}

// VCStatus vc status
type VCStatus struct {
	CurrentStatus string `json:"currentStatus"`
	StatusReason  string `json:"statusReason"`
}

// New returns new Credential Status List
func New(provider storage.Provider, url string, listSize int, c crypto) (*CredentialStatusManager, error) {
	err := provider.CreateStore(credentialStatusStore)
	if err != nil {
		if !errors.Is(err, storage.ErrDuplicateStore) {
			return nil, err
		}
	}

	store, err := provider.OpenStore(credentialStatusStore)
	if err != nil {
		return nil, err
	}

	return &CredentialStatusManager{store: store, url: url, listSize: listSize, crypto: c}, nil
}

// CreateStatusID create status id
func (c *CredentialStatusManager) CreateStatusID() (*verifiable.TypedID, error) {
	cslWrapper, err := c.getLatestCSL()
	if err != nil {
		return nil, err
	}

	cslWrapper.Size++

	if err := c.storeCSL(cslWrapper); err != nil {
		return nil, err
	}

	if cslWrapper.Size == c.listSize {
		id, err := strconv.Atoi(cslWrapper.ID)
		if err != nil {
			return nil, err
		}

		id++

		if err := c.store.Put(latestListID, []byte(strconv.FormatInt(int64(id), 10))); err != nil {
			return nil, fmt.Errorf("failed to store latest list ID in store: %w", err)
		}
	}

	return &verifiable.TypedID{ID: cslWrapper.CSL.ID, Type: CredentialStatusType}, nil
}

// UpdateVCStatus update vc status
func (c *CredentialStatusManager) UpdateVCStatus(v *verifiable.Credential, profile *vcprofile.DataProfile,
	status, statusReason string) error {
	cslWrapper, err := c.getCSLWrapper(v.Status.ID)
	if err != nil {
		return err
	}

	signOpts, err := prepareSigningOpts(profile, v.Proofs)
	if err != nil {
		return err
	}

	statusCredential, err := c.createStatusCredential(v, status, statusReason)
	if err != nil {
		return err
	}

	signedStatusCredential, err := c.crypto.SignCredential(profile, statusCredential, signOpts...)
	if err != nil {
		return err
	}

	for i, vc := range cslWrapper.CSL.VC {
		if strings.Contains(vc, v.ID) {
			cslWrapper.CSL.VC = append(cslWrapper.CSL.VC[:i], cslWrapper.CSL.VC[i+1:]...)
			break
		}
	}

	signedStatusCredentialBytes, err := signedStatusCredential.MarshalJSON()
	if err != nil {
		return err
	}

	cslWrapper.CSL.VC = append(cslWrapper.CSL.VC, string(signedStatusCredentialBytes))

	return c.storeCSL(cslWrapper)
}

// GetCSL get csl
func (c *CredentialStatusManager) GetCSL(id string) (*CSL, error) {
	cslWrapper, err := c.getCSLWrapper(id)
	if err != nil {
		return nil, err
	}

	return cslWrapper.CSL, nil
}

func (c *CredentialStatusManager) getCSLWrapper(id string) (*cslWrapper, error) {
	cslWrapperBytes, err := c.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	var w cslWrapper
	if err := json.Unmarshal(cslWrapperBytes, &w); err != nil {
		return nil, fmt.Errorf("failed to unmarshal csl bytes: %w", err)
	}

	return &w, nil
}

func (c *CredentialStatusManager) createStatusCredential(v *verifiable.Credential, status,
	statusReason string) (*verifiable.Credential, error) {
	v.Subject = VCStatus{CurrentStatus: status, StatusReason: statusReason}
	v.Proofs = []verifiable.Proof{}

	cred, err := v.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create credential marshalling failed: %s", err.Error())
	}

	validatedStatusCred, err := verifiable.ParseCredential(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %s", err.Error())
	}

	return validatedStatusCred, nil
}

func (c *CredentialStatusManager) getLatestCSL() (*cslWrapper, error) {
	// get latest id
	id, err := c.store.Get(latestListID)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			if errPut := c.store.Put(latestListID, []byte("1")); errPut != nil {
				return nil, fmt.Errorf("failed to store latest list ID in store: %w", errPut)
			}

			return &cslWrapper{&CSL{ID: c.url + "/1"}, 0, "1"}, nil
		}

		return nil, fmt.Errorf("failed to get latestListID from store: %w", err)
	}

	statusID := c.url + "/" + string(id)
	w, err := c.getCSLWrapper(statusID)

	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			return &cslWrapper{&CSL{ID: statusID}, 0, string(id)}, nil
		}

		return nil, fmt.Errorf("failed to get csl from store: %w", err)
	}

	return w, nil
}

func (c *CredentialStatusManager) storeCSL(cslWrapper *cslWrapper) error {
	cslWrapperBytes, err := json.Marshal(cslWrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal csl struct: %w", err)
	}

	if err := c.store.Put(cslWrapper.CSL.ID, cslWrapperBytes); err != nil {
		return fmt.Errorf("failed to store csl in store: %w", err)
	}

	return nil
}

// prepareSigningOpts prepares signing opts from recently issued proof of given credential
func prepareSigningOpts(profile *vcprofile.DataProfile, proofs []verifiable.Proof) ([]vccrypto.SigningOpts, error) {
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
	if vm != profile.Creator {
		signingOpts = append(signingOpts, vccrypto.WithVerificationMethod(vm))
	}

	signType, err := getStringValue(jsonKeySignaturefType, proof)
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
