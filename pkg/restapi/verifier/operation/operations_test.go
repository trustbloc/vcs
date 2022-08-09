/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trustbloc/vcs/pkg/storage/ariesprovider"

	vcsstorage "github.com/trustbloc/vcs/pkg/storage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	vdrmock "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	cslstatus "github.com/trustbloc/vcs/pkg/doc/vc/status/csl"
	"github.com/trustbloc/vcs/pkg/internal/common/utils"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
)

const (
	assertionMethod = "assertionMethod"
	testProfileID   = "testProfileID"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&Config{
			StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
			VDRI:          &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test failure", func(t *testing.T) {
		controller, err := New(&Config{
			StoreProvider: ariesprovider.New(&ariesmockstorage.MockStoreProvider{
				ErrOpenStoreHandle: errors.New("error creating the store"),
			}),
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
		require.Nil(t, controller)
	})
}

func TestCreateProfile(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	endpoint := profileEndpoint
	handler := getHandler(t, op, endpoint, http.MethodPost)

	t.Run("create profile - success", func(t *testing.T) {
		vReq := &vcsstorage.VerifierProfile{
			ID:                 uuid.New().String(),
			Name:               "test",
			CredentialChecks:   []string{proofCheck, statusCheck},
			PresentationChecks: []string{proofCheck},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		profileRes := &vcsstorage.VerifierProfile{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, vReq, profileRes)
	})

	t.Run("create profile - invalid request", func(t *testing.T) {
		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, []byte("invalid-json"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("create profile - missing profile id", func(t *testing.T) {
		vReq := &vcsstorage.VerifierProfile{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile id")
	})

	t.Run("create profile - missing profile name", func(t *testing.T) {
		vReq := &vcsstorage.VerifierProfile{
			ID: "test1",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile name")
	})

	t.Run("create profile - invalid credential checks", func(t *testing.T) {
		vReq := &vcsstorage.VerifierProfile{
			ID:               "test1",
			Name:             "test 1",
			CredentialChecks: []string{proofCheck, statusCheck, "invalidCheck"},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid credential check option - invalidCheck")
	})

	t.Run("create profile - invalid presentation checks", func(t *testing.T) {
		vReq := &vcsstorage.VerifierProfile{
			ID:                 "test1",
			Name:               "test 1",
			PresentationChecks: []string{proofCheck, "invalidCheck"},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid presentation check option - invalidCheck")
	})

	t.Run("create profile - profile already exists", func(t *testing.T) {
		vReq := &vcsstorage.VerifierProfile{
			ID:   "test1",
			Name: "test 1",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "profile test1 already exists")
	})

	t.Run("create profile - get profile error", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: ariesprovider.New(&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					Store:  make(map[string]ariesmockstorage.DBEntry),
					ErrGet: errors.New("get error"),
				},
			}),
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)

		endpoint := profileEndpoint
		handler := getHandler(t, op, endpoint, http.MethodPost)

		vReq := &vcsstorage.VerifierProfile{
			ID:   "test1",
			Name: "test 1",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "get error")
	})

	t.Run("create profile - profile fetch db error", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: ariesprovider.New(&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					Store:  make(map[string]ariesmockstorage.DBEntry),
					ErrPut: errors.New("save error"),
				},
			}),
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)

		endpoint := profileEndpoint
		handler := getHandler(t, op, endpoint, http.MethodPost)

		vReq := &vcsstorage.VerifierProfile{
			ID:   "test1",
			Name: "test 1",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "save error")
	})
}

func TestGetProfile(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	endpoint := getProfileEndpoint
	handler := getHandler(t, op, endpoint, http.MethodGet)

	urlVars := make(map[string]string)

	t.Run("get profile - success", func(t *testing.T) {
		vReq := vcsstorage.VerifierProfile{
			ID: "test",
		}

		err := op.profileStore.Put(vReq)
		require.NoError(t, err)

		urlVars[profileIDPathParam] = vReq.ID

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)

		profileRes := &vcsstorage.VerifierProfile{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, vReq.ID, profileRes.ID)
	})

	t.Run("get profile - no data found", func(t *testing.T) {
		urlVars[profileIDPathParam] = "invalid-name"

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "data not found")
	})
}

func TestDeleteProfileHandler(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
		VDRI:          &vdrmock.MockVDRegistry{},
	})
	require.NoError(t, err)

	endpoint := deleteProfileEndpoint
	handler := getHandler(t, op, endpoint, http.MethodDelete)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = testProfileID

	t.Run("delete profile - success", func(t *testing.T) {
		saveTestProfile(t, op)

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("delete profile - other error in delete profile from store", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: ariesprovider.New(&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					Store:     make(map[string]ariesmockstorage.DBEntry),
					ErrDelete: errors.New("delete error"),
				},
			}),
			VDRI: &vdrmock.MockVDRegistry{},
		})
		require.NoError(t, err)
		handler := getHandler(t, op, endpoint, http.MethodDelete)

		saveTestProfile(t, op)
		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "delete error")
	})
}

func TestVerifyCredential(t *testing.T) {
	loader := testutil.DocumentLoader(t)

	vc, err := verifiable.ParseCredential([]byte(prCardVC), verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	op, err := New(&Config{
		VDRI:           &vdrmock.MockVDRegistry{},
		StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
		RequestTokens:  map[string]string{cslRequestTokenName: "tk1"},
		DocumentLoader: loader,
	})
	require.NoError(t, err)

	vReq := vcsstorage.VerifierProfile{
		ID:                 "test",
		Name:               "test verifier",
		CredentialChecks:   []string{proofCheck, statusCheck},
		PresentationChecks: []string{proofCheck},
	}

	err = op.profileStore.Put(vReq)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = vReq.ID

	endpoint := "/test/verifier/credentials/verify"
	didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

	verificationsHandler := getHandler(t, op, credentialsVerificationEndpoint, http.MethodPost)

	t.Run("credential verification - success", func(t *testing.T) {
		pubKey, privKey, errGenerateKey := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, errGenerateKey)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, errNew := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, errNew)

		err = ops.profileStore.Put(vReq)
		require.NoError(t, err)

		encodeBits, errNew := utils.NewBitString(2).EncodeBits()
		require.NoError(t, errNew)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(fmt.Sprintf(revocationListVC, didDoc.ID, encodeBits))),
		}}

		vc.Status = &verifiable.TypedID{
			ID:   uuid.New().URN(),
			Type: cslstatus.StatusList2021Entry,
			CustomFields: map[string]interface{}{
				cslstatus.StatusListIndex:      "1",
				cslstatus.StatusListCredential: "http://example.com/status/100",
				cslstatus.StatusPurpose:        "revocation",
			},
		}

		vcBytes, errMarshal := vc.MarshalJSON()
		require.NoError(t, errMarshal)

		// verify credential
		handler := getHandler(t, ops, credentialsVerificationEndpoint, http.MethodPost)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, string(vcBytes), didID, verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, errMarshal := json.Marshal(vReq)
		require.NoError(t, errMarshal)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)
		require.Equal(t, http.StatusOK, rr.Code)

		verificationResp := &CredentialsVerificationSuccessResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 2, len(verificationResp.Checks))
	})

	t.Run("credential verification - vc issuer not equal vc list status", func(t *testing.T) {
		pubKey, privKey, errGenerateKey := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, errGenerateKey)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, errNew := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, errNew)

		err = ops.profileStore.Put(vReq)
		require.NoError(t, err)

		encodeBits, errNew := utils.NewBitString(2).EncodeBits()
		require.NoError(t, errNew)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(fmt.Sprintf(revocationListVC, "did:ex:12", encodeBits))),
		}}

		vc.Status = &verifiable.TypedID{
			ID:   uuid.New().URN(),
			Type: cslstatus.StatusList2021Entry,
			CustomFields: map[string]interface{}{
				cslstatus.StatusListIndex:      "1",
				cslstatus.StatusListCredential: "http://example.com/status/100",
				cslstatus.StatusPurpose:        "revocation",
			},
		}

		vcBytes, errMarshal := vc.MarshalJSON()
		require.NoError(t, errMarshal)

		// verify credential
		handler := getHandler(t, ops, credentialsVerificationEndpoint, http.MethodPost)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, string(vcBytes), didID, verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, errMarshal := json.Marshal(vReq)
		require.NoError(t, errMarshal)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "issuer of the credential do not match vc revocation list issuer")
	})

	t.Run("credential verification - invalid profile", func(t *testing.T) {
		ops, errNew := New(&Config{
			VDRI:          &vdrmock.MockVDRegistry{},
			StoreProvider: ariesprovider.New(ariesmemstorage.NewProvider()),
		})
		require.NoError(t, errNew)

		signPresentationHandler := getHandler(t, ops, credentialsVerificationEndpoint, http.MethodPost)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid verifier profile")
	})

	t.Run("credential verification - request doesn't contain checks", func(t *testing.T) {
		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, errMarshal := json.Marshal(req)
		require.NoError(t, errMarshal)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		// verify that the default check was performed
		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable credential doesn't contains proof", verificationResp.Checks[0].Error)
	})

	t.Run("credential verification - invalid credential", func(t *testing.T) {
		req := &CredentialsVerificationRequest{
			Credential: []byte(invalidVC),
		}

		reqBytes, errMarshal := json.Marshal(req)
		require.NoError(t, errMarshal)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request: build new credential")
	})

	t.Run("credential verification - proof check failure", func(t *testing.T) {
		// no proof in VC
		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, errMarshal := json.Marshal(req)
		require.NoError(t, errMarshal)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable credential doesn't contains proof", verificationResp.Checks[0].Error)

		// proof validation error (DID not found)
		req = &CredentialsVerificationRequest{
			Credential: []byte(validVCWithProof),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "DID does not exist")
	})

	t.Run("credential verification - status check failure", func(t *testing.T) {
		t.Run("status check failure - vc status not exist", func(t *testing.T) {
			vc.Status = nil
			vcBytes, errMarshal := vc.MarshalJSON()
			require.NoError(t, errMarshal)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, errMarshal := json.Marshal(req)
			require.NoError(t, errMarshal)

			rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "vc status not exist")
		})

		t.Run("status check failure - wrong vc status type", func(t *testing.T) {
			vc.Status = &verifiable.TypedID{
				ID:   "http://example.com/status/100#1",
				Type: "NotMatch",
				CustomFields: map[string]interface{}{
					cslstatus.StatusListIndex:      "1",
					cslstatus.StatusListCredential: "http://example.com/status/100",
					cslstatus.StatusPurpose:        "revocation",
				},
			}

			vcBytes, errMarshal := vc.MarshalJSON()
			require.NoError(t, errMarshal)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, errMarshal := json.Marshal(req)
			require.NoError(t, errMarshal)

			rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "vc status NotMatch not supported")
		})

		t.Run("status check failure - statusListIndex not exist", func(t *testing.T) {
			vc.Status = &verifiable.TypedID{
				ID:   uuid.New().URN(),
				Type: cslstatus.StatusList2021Entry,
				CustomFields: map[string]interface{}{
					cslstatus.StatusListCredential: "http://example.com/status/100",
				},
			}

			vcBytes, errMarshal := vc.MarshalJSON()
			require.NoError(t, errMarshal)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, errMarshal := json.Marshal(req)
			require.NoError(t, errMarshal)

			rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "statusListIndex field not exist in vc status")
		})

		t.Run("status check failure - statusListCredential not exist", func(t *testing.T) {
			vc.Status = &verifiable.TypedID{
				ID:   uuid.New().URN(),
				Type: cslstatus.StatusList2021Entry,
				CustomFields: map[string]interface{}{
					cslstatus.StatusListIndex: "1",
				},
			}

			vcBytes, errMarshal := vc.MarshalJSON()
			require.NoError(t, errMarshal)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, errMarshal := json.Marshal(req)
			require.NoError(t, errMarshal)

			rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "statusListCredential field not exist in vc status")
		})

		t.Run("status check failure - error fetching status", func(t *testing.T) {
			vc.Status = &verifiable.TypedID{
				ID:   uuid.New().URN(),
				Type: cslstatus.StatusList2021Entry,
				CustomFields: map[string]interface{}{
					cslstatus.StatusListIndex:      "1",
					cslstatus.StatusListCredential: "http://example.com/status/100",
				},
			}

			vcBytes, errMarshal := vc.MarshalJSON()
			require.NoError(t, errMarshal)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, errMarshal := json.Marshal(req)
			require.NoError(t, errMarshal)

			rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "failed to fetch the status")
		})

		t.Run("status check failure - revoked", func(t *testing.T) {
			require.NoError(t, err)

			bitString := utils.NewBitString(2)
			err := bitString.Set(1, true)
			require.NoError(t, err)

			encodeBits, err := bitString.EncodeBits()
			require.NoError(t, err)

			op.httpClient = &mockHTTPClient{doValue: &http.Response{
				StatusCode: http.StatusOK,
				Body: ioutil.NopCloser(strings.NewReader(fmt.Sprintf(revocationListVC,
					vc.Issuer.ID, encodeBits))),
			}}

			vc.Status = &verifiable.TypedID{
				ID:   uuid.New().URN(),
				Type: cslstatus.StatusList2021Entry,
				CustomFields: map[string]interface{}{
					cslstatus.StatusListIndex:      "1",
					cslstatus.StatusListCredential: "http://example.com/status/100",
					cslstatus.StatusPurpose:        "revocation",
				},
			}

			vcBytes, err := vc.MarshalJSON()
			require.NoError(t, err)

			req := &CredentialsVerificationRequest{
				Credential: vcBytes,
				Opts: &CredentialsVerificationOptions{
					Checks: []string{statusCheck},
				},
			}

			reqBytes, err := json.Marshal(req)
			require.NoError(t, err)

			rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "Revoked")
		})
	})

	t.Run("credential verification - invalid check", func(t *testing.T) {
		invalidCheckName := "invalidCheckName"

		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
			Opts: &CredentialsVerificationOptions{
				Checks: []string{invalidCheckName},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, invalidCheckName, verificationResp.Checks[0].Check)
		require.Equal(t, "check not supported", verificationResp.Checks[0].Error)
	})

	t.Run("credential verification - invalid json input", func(t *testing.T) {
		rr := serveHTTPMux(t, verificationsHandler, endpoint, []byte("invalid input"), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("credential verification - invalid challenge and domain", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID

		op, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = op.profileStore.Put(vReq)
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, credentialsVerificationEndpoint, http.MethodPost)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, didID, verificationMethod, domain,
				"invalid-challenge"),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, didID, verificationMethod, "invalid-domain", challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck},
				Domain:    domain,
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")

		// fail when proof has challenge and no challenge in the options
		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, didID, verificationMethod, domain, challenge),
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		// fail when proof has domain and no domain in the options
		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, didID, verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")
	})

	t.Run("credential verification - invalid vc proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.AssertionMethod = nil
		verificationMethod := didDoc.VerificationMethod[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = ops.profileStore.Put(vReq)
		require.NoError(t, err)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader("")),
		}}

		vc.Status = &verifiable.TypedID{
			ID:   uuid.New().URN(),
			Type: cslstatus.StatusList2021Entry,
			CustomFields: map[string]interface{}{
				cslstatus.StatusListIndex:      "94567",
				cslstatus.StatusListCredential: "http://example.com/status/100",
				cslstatus.StatusPurpose:        "revocation",
			},
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, credentialsVerificationEndpoint, http.MethodPost)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, string(vcBytes), didID, verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable credential proof purpose validation error :"+
			" unable to find matching assertionMethod key IDs for given verification method")
	})

	t.Run("credential verification - issuer is not the controller of verification method", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = ops.profileStore.Put(vReq)
		require.NoError(t, err)

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, credentialsVerificationEndpoint, http.MethodPost)

		vReq := &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, string(vcBytes), "did:invalid:issuer", verificationMethod, domain, challenge),
			Opts: &CredentialsVerificationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "controller of verification method doesn't match the issuer")
	})
}

func TestVerifyPresentation(t *testing.T) {
	loader := testutil.DocumentLoader(t)

	op, err := New(&Config{
		VDRI:           &vdrmock.MockVDRegistry{},
		StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
		DocumentLoader: loader,
	})
	require.NoError(t, err)

	vReq := vcsstorage.VerifierProfile{
		ID:                 "test",
		Name:               "test verifier",
		CredentialChecks:   []string{proofCheck, statusCheck},
		PresentationChecks: []string{proofCheck, statusCheck},
	}

	err = op.profileStore.Put(vReq)
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[profileIDPathParam] = vReq.ID

	endpoint := "/test/verifier/presentations/verify"
	verificationsHandler := getHandler(t, op, presentationsVerificationEndpoint, http.MethodPost)

	t.Run("presentation verification - success", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID

		op, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		encodeBits, errNew := utils.NewBitString(2).EncodeBits()
		require.NoError(t, errNew)

		op.httpClient = &mockHTTPClient{doValue: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(fmt.Sprintf(revocationListVC, didDoc.ID, encodeBits))),
		}}

		err = op.profileStore.Put(vReq)
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, presentationsVerificationEndpoint, http.MethodPost)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)

		verificationResp := &VerifyPresentationSuccessResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 2, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0])
		require.Equal(t, statusCheck, verificationResp.Checks[1])
	})

	t.Run("presentation verification - invalid profile", func(t *testing.T) {
		ops, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, presentationsVerificationEndpoint, http.MethodPost)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid verifier profile")
	})

	t.Run("presentation verification - invalid vp", func(t *testing.T) {
		ops, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = ops.profileStore.Put(vReq)
		require.NoError(t, err)

		vReq := &VerifyPresentationRequest{
			Presentation: []byte(prCardVC),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck, statusCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		signPresentationHandler := getHandler(t, ops, presentationsVerificationEndpoint, http.MethodPost)

		rr := serveHTTPMux(t, signPresentationHandler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		// verify that the default check was performed
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Greater(t, len(verificationResp.Checks), 0)
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, "verifiable presentation proof validation error")
	})

	t.Run("presentation verification - request doesn't contain checks", func(t *testing.T) {
		req := &VerifyPresentationRequest{
			Presentation: []byte(vpWithoutProof),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		// verify that the default check was performed
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 2, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, " verifiable credential proof validation error")
	})

	t.Run("presentation verification - proof check failure", func(t *testing.T) {
		// no proof in VC
		req := &VerifyPresentationRequest{
			Presentation: []byte(vpWithoutProof),
			Opts: &VerifyPresentationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, "verifiable credential proof validation error")

		// proof validation error (DID not found)
		req = &VerifyPresentationRequest{
			Presentation: []byte(validVCWithProof),
			Opts: &VerifyPresentationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp = &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, "proof validation error")
	})

	t.Run("presentation verification - invalid check", func(t *testing.T) {
		invalidCheckName := "invalidCheckName"

		req := &VerifyPresentationRequest{
			Presentation: []byte(vpWithoutProof),
			Opts: &VerifyPresentationOptions{
				Checks: []string{invalidCheckName},
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTPMux(t, verificationsHandler, endpoint, reqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, invalidCheckName, verificationResp.Checks[0].Check)
		require.Equal(t, "check not supported", verificationResp.Checks[0].Error)
	})

	t.Run("presentation verification - invalid json input", func(t *testing.T) {
		rr := serveHTTPMux(t, verificationsHandler, endpoint, []byte("invalid input"), urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("presentation verification - invalid challenge and domain", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:xyz"

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID

		op, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = op.profileStore.Put(vReq)
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, presentationsVerificationEndpoint, http.MethodPost)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, uuid.New().String()),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Domain:    domain,
				Challenge: challenge,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, "invalid-domain", challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Domain:    domain,
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")

		// fail when proof has challenge and no challenge in the options
		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, challenge),
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid challenge in the proof")

		// fail when proof has domain and no domain in the options
		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
			},
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")
	})

	t.Run("presentation verification - invalid vp proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:xyz123"

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.Authentication = nil
		verificationMethod := didDoc.VerificationMethod[0].ID

		op, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = op.profileStore.Put(vReq)
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, presentationsVerificationEndpoint, http.MethodPost)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable presentation proof purpose validation error :"+
			" unable to find matching authentication key IDs for given verification method")
	})

	t.Run("presentation verification - invalid vc proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:abc123"

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.AssertionMethod = nil
		verificationMethod := didDoc.VerificationMethod[0].ID

		op, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = op.profileStore.Put(vReq)
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, presentationsVerificationEndpoint, http.MethodPost)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable credential proof purpose validation error : unable"+
			" to find matching assertionMethod key IDs for given verification method")
	})

	t.Run("presentation verification - holder is not the controller of verification method", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:abc123"

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.VerificationMethod[0].ID

		op, err := New(&Config{
			VDRI:           &vdrmock.MockVDRegistry{ResolveValue: didDoc},
			StoreProvider:  ariesprovider.New(ariesmemstorage.NewProvider()),
			DocumentLoader: loader,
		})
		require.NoError(t, err)

		err = op.profileStore.Put(vReq)
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, presentationsVerificationEndpoint, http.MethodPost)

		vReq := &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, "did:invalid:holder", verificationMethod,
				didID, verificationMethod, domain, challenge),
			Opts: &VerifyPresentationOptions{
				Checks:    []string{proofCheck},
				Challenge: challenge,
				Domain:    domain,
			},
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTPMux(t, handler, endpoint, vReqBytes, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "controller of verification method doesn't match the holder")
	})
}

func TestValidateProof(t *testing.T) {
	proof := make(map[string]interface{})
	key := "challenge"
	value := uuid.New().String()

	proof[key] = value

	// success
	err := validateProofData(proof, key, value)
	require.NoError(t, err)

	// fail - not a string
	proof[key] = 234
	err = validateProofData(proof, key, value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid challenge in the proof")

	// fail - invalid
	proof[key] = "invalid-data"
	err = validateProofData(proof, key, value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid challenge in the proof")
}

func TestValidateProofPurpose(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didID := "did:test:xyz123"

	didDoc := createDIDDoc(didID, pubKey)
	kid := didDoc.VerificationMethod[0].ID

	proof := make(map[string]interface{})
	key := "challenge"
	value := uuid.New().String()

	proof[proofPurpose] = assertionMethod
	proof[verificationMethod] = kid

	// success
	err = validateProofPurpose(proof, kid, didDoc)
	require.NoError(t, err)

	// fail - no value
	delete(proof, proofPurpose)
	err = validateProofPurpose(proof, kid, didDoc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof doesn't have purpose")

	// fail - not a string
	proof[proofPurpose] = 234
	err = validateProofPurpose(proof, kid, didDoc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof purpose is not a string")

	// fail - invalid
	proof[key] = "invalid-data"
	err = validateProofData(proof, key, value)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid challenge in the proof")
}

func TestGetVerificationMethodFromProof(t *testing.T) {
	proof := make(map[string]interface{})
	key := verificationMethod
	value := uuid.New().String()

	proof[key] = value

	// success
	verificationMethod, err := getVerificationMethodFromProof(proof)
	require.NoError(t, err)
	require.Equal(t, value, verificationMethod)

	// fail - not a string
	proof[key] = 234
	verificationMethod, err = getVerificationMethodFromProof(proof)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof verification method is not a string")
	require.Empty(t, verificationMethod)

	// fail - no data
	delete(proof, key)
	verificationMethod, err = getVerificationMethodFromProof(proof)
	require.Error(t, err)
	require.Contains(t, err.Error(), "proof doesn't have verification method")
	require.Empty(t, verificationMethod)
}

func TestGetDIDDocFromProof(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didID := "did:test:abc789"

	didDoc := createDIDDoc(didID, pubKey)
	verificationMethod := didDoc.VerificationMethod[0].ID

	vdr := &vdrmock.MockVDRegistry{ResolveValue: didDoc}

	// success
	doc, err := getDIDDocFromProof(verificationMethod, vdr)
	require.NoError(t, err)
	require.NotNil(t, doc)

	// fail - verification method not in correct format
	verificationMethod = "invalid-format"

	doc, err = getDIDDocFromProof(verificationMethod, vdr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verificationMethod value invalid-format should be in did#keyID format")
	require.Nil(t, doc)

	// fail - resolve error
	vdr = &vdrmock.MockVDRegistry{ResolveErr: errors.New("resolve error")}
	verificationMethod = didDoc.VerificationMethod[0].ID

	doc, err = getDIDDocFromProof(verificationMethod, vdr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolve error")
	require.Nil(t, doc)
}

type mockHTTPClient struct {
	doValue *http.Response
	doErr   error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.doValue, m.doErr
}

func getSignedVC(t *testing.T, privKey []byte, vcJSON, didID, verificationMethod, domain, challenge string) []byte {
	t.Helper()

	loader := testutil.DocumentLoader(t)

	vc, err := verifiable.ParseCredential([]byte(vcJSON), verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	vc.Issuer.ID = didID

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	signerSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithCompactProof())
	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   signerSuite,
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &created,
		VerificationMethod:      verificationMethod,
		Domain:                  domain,
		Challenge:               challenge,
		Purpose:                 vccrypto.AssertionMethod,
	}, jsonld.WithDocumentLoader(loader))
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	signedVC, err := vc.MarshalJSON()
	require.NoError(t, err)

	return signedVC
}

func getSignedVP(t *testing.T, privKey []byte, vcJSON, holderDID, vpVerificationMethod, issuerDID, vcVerificationMethod, domain, challenge string) []byte { // nolint
	t.Helper()

	signedVC := getSignedVC(t, privKey, vcJSON, issuerDID, vcVerificationMethod, "", "")

	loader := testutil.DocumentLoader(t)

	vc, err := verifiable.ParseCredential(signedVC, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(loader))
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	require.NoError(t, err)

	vp.Holder = holderDID

	signerSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithCompactProof())
	err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   signerSuite,
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &created,
		VerificationMethod:      vpVerificationMethod,
		Domain:                  domain,
		Challenge:               challenge,
		Purpose:                 vccrypto.Authentication,
	}, jsonld.WithDocumentLoader(loader))
	require.NoError(t, err)

	signedVP, err := vp.MarshalJSON()
	require.NoError(t, err)

	return signedVP
}

type ed25519TestSigner struct {
	privateKey []byte
}

func (s *ed25519TestSigner) Sign(doc []byte) ([]byte, error) {
	if l := len(s.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("ed25519: bad private key length")
	}

	return ed25519.Sign(s.privateKey, doc), nil
}

func getEd25519TestSigner(privKey []byte) *ed25519TestSigner {
	return &ed25519TestSigner{privateKey: privKey}
}

func getHandler(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	t.Helper()

	return getHandlerWithError(t, op, pathToLookup, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	t.Helper()

	return handlerLookup(t, op, pathToLookup, methodToLookup)
}

func handlerLookup(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == pathToLookup && h.Method() == methodToLookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder { // nolint: unparam,lll
	t.Helper()

	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, httpReq)

	return rr
}

func serveHTTPMux(t *testing.T, handler Handler, endpoint string, reqBytes []byte,
	urlVars map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
}

func saveTestProfile(t *testing.T, op *Operation) {
	t.Helper()

	vReq := vcsstorage.VerifierProfile{
		ID: testProfileID,
	}

	err := op.profileStore.Put(vReq)
	require.NoError(t, err)
}

func createDIDDoc(didID string, pubKey []byte) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	creator := didID + "#key-1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: ariesmodel.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
	}
}

const (
	prCardVC = `{
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1",
        "https://w3id.org/vc/status-list/2021/v1"
	  ],
	  "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	  "type": [
		"VerifiableCredential",
		"PermanentResidentCard"
	  ],
	  "name": "Permanent Resident Card",
	  "description": "Permanent Resident Card",
	  "issuer": "did:example:28394728934792387",
	  "issuanceDate": "2019-12-03T12:19:52Z",
	  "expirationDate": "2029-12-03T12:19:52Z",
	   "credentialStatus": {
          "id": "https://example.com",
          "type": "StatusList2021Entry",
          "statusPurpose": "revocation",
          "statusListIndex": "1",
          "statusListCredential": "https://example.com/credentials/status/3"
       },
	  "credentialSubject": {
		"id": "did:example:b34ca6cd37bbf23",
		"type": [
		  "PermanentResident",
		  "Person"
		],
		"givenName": "JOHN",
		"familyName": "SMITH",
		"gender": "Male",
		"image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
		"residentSince": "2015-01-01",
		"lprCategory": "C09",
		"lprNumber": "999-999-999",
		"commuterClassification": "C1",
		"birthCountry": "Bahamas",
		"birthDate": "1958-07-17"
	  }
	}
	`

	invalidVC = `{
		"name": "issuer"
	}`

	validVCWithProof = `{	
	   "@context":[	
		  "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/vc/status-list/2021/v1"
	   ],	
	   "credentialSchema":[	
	   ],	
	   "credentialStatus": {
          "id": "https://example.com",
          "type": "StatusList2021Entry",
          "statusPurpose": "revocation",
          "statusListIndex": "94567",
          "statusListCredential": "https://example.com/credentials/status/3"
       },	
	   "credentialSubject":{	
		  "id":"did:example:ebfeb1f712ebc6f1c276e12ec21"	
	   },	
	   "id":"http://example.edu/credentials/1872",	
	   "issuanceDate":"2010-01-01T19:23:24Z",	
	   "issuer":{	
		  "id":"did:example:76e12ec712ebc6f1c221ebfeb1f",	
		  "name":"Example University"	
	   },	
	   "proof":{	
		  "created":"2020-03-23T17:20:15Z",	
		  "jws":"eyJhbGciOiJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..` +
		`-M4JuuSvRurmWqX0S_x2eXg-ZaaDhkAUQ1GlV9DjD0WKZUKJefSkSgevYro64aFzQEa_gK7b1akJCB7XZtH1Aw",	
		  "type":"Ed25519Signature2018",	
		  "verificationMethod":"did:trustbloc:testnet.trustbloc.local:EiBpn9XWyJlGpny_` +
		`ViTH75fi43ThiIlGUyc1rQEb3VgreQ==#key-1"	
	   },	
	   "type":"VerifiableCredential"	
	}`

	revocationListVC = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "https://example.com/credentials/status/3",
  "type": ["VerifiableCredential", "RevocationList2020Credential"],
  "issuer": "%s",
  "issuanceDate": "2020-04-05T14:27:40Z",
  "credentialSubject": {
    "id": "https://example.com/status/3#list",
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "%s"
  		}
	}`

	vpWithoutProof = `{	
		"@context": [	
			"https://www.w3.org/2018/credentials/v1",	
			"https://www.w3.org/2018/credentials/examples/v1",
            "https://w3id.org/vc/status-list/2021/v1"
		],	
		"id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",	
		"type": "VerifiablePresentation",	
		"verifiableCredential": [{	
			"@context": [	
				"https://www.w3.org/2018/credentials/v1",	
				"https://www.w3.org/2018/credentials/examples/v1"	
			],	
			"id": "http://example.edu/credentials/1872",	
			"type": "VerifiableCredential",	
			"credentialSubject": {	
				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"	
			},	
			"issuer": {	
				"id": "did:example:76e12ec712ebc6f1c221ebfeb1f",	
				"name": "Example University"	
			},	
			"issuanceDate": "2010-01-01T19:23:24Z",	
			"credentialStatus": {
              "id": "https://example.com",
              "type": "StatusList2021Entry",
          	  "statusPurpose": "revocation",
              "statusListIndex": "94567",
              "statusListCredential": "https://example.com/credentials/status/3"
            }	
		}],	
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",	
		"refreshService": {	
			"id": "https://example.edu/refresh/3732",	
			"type": "ManualRefreshService2018"	
		}	
	}`
)
