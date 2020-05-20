/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrimock "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"

	vccrypto "github.com/trustbloc/edge-service/pkg/doc/vc/crypto"
	"github.com/trustbloc/edge-service/pkg/doc/vc/profile/verifier"
	cslstatus "github.com/trustbloc/edge-service/pkg/doc/vc/status/csl"
)

const (
	assertionMethod = "assertionMethod"
)

func Test_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&Config{
			StoreProvider: memstore.NewProvider(),
			VDRI:          &vdrimock.MockVDRIRegistry{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("test failure", func(t *testing.T) {
		controller, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrCreateStore: errors.New("error creating the store")},
			VDRI:          &vdrimock.MockVDRIRegistry{},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the store")
		require.Nil(t, controller)
	})
}

func TestCreateProfile(t *testing.T) {
	op, err := New(&Config{
		StoreProvider: memstore.NewProvider(),
		VDRI:          &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	endpoint := profileEndpoint
	handler := getHandler(t, op, endpoint)

	t.Run("create profile - success", func(t *testing.T) {
		vReq := &verifier.ProfileData{
			ID:   uuid.New().String(),
			Name: "test",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusCreated, rr.Code)

		profileRes := &verifier.ProfileData{}
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
		vReq := &verifier.ProfileData{}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile id")
	})

	t.Run("create profile - missing profile name", func(t *testing.T) {
		vReq := &verifier.ProfileData{
			ID: "test1",
		}

		vReqBytes, err := json.Marshal(vReq)
		require.NoError(t, err)

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing profile name")
	})

	t.Run("create profile - profile already exists", func(t *testing.T) {
		vReq := &verifier.ProfileData{
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

	t.Run("create profile - profile fetch db error", func(t *testing.T) {
		op, err := New(&Config{
			StoreProvider: &mockstorage.Provider{Store: &mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("save error")},
			},
			VDRI: &vdrimock.MockVDRIRegistry{},
		})
		require.NoError(t, err)

		endpoint := profileEndpoint
		handler := getHandler(t, op, endpoint)

		vReq := &verifier.ProfileData{
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
		StoreProvider: memstore.NewProvider(),
		VDRI:          &vdrimock.MockVDRIRegistry{},
	})
	require.NoError(t, err)

	endpoint := getProfileEndpoint
	handler := getHandler(t, op, endpoint)

	urlVars := make(map[string]string)

	t.Run("get profile - success", func(t *testing.T) {
		vReq := &verifier.ProfileData{
			ID: "test",
		}

		err := op.profileStore.SaveProfile(vReq)
		require.NoError(t, err)

		urlVars[profileIDPathParam] = vReq.ID

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)

		profileRes := &verifier.ProfileData{}
		err = json.Unmarshal(rr.Body.Bytes(), &profileRes)
		require.NoError(t, err)
		require.Equal(t, vReq.ID, profileRes.ID)
	})

	t.Run("get profile - no data found", func(t *testing.T) {
		urlVars[profileIDPathParam] = "invalid-name"

		rr := serveHTTPMux(t, handler, endpoint, nil, urlVars)

		fmt.Println(rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "store does not have a value associated with this key")
	})
}

func TestVerifyCredential(t *testing.T) {
	vc, err := verifiable.NewUnverifiedCredential([]byte(prCardVC))
	require.NoError(t, err)

	vc.Context = append(vc.Context, cslstatus.Context)

	op, err := New(&Config{
		VDRI:          &vdrimock.MockVDRIRegistry{},
		StoreProvider: memstore.NewProvider(),
	})
	require.NoError(t, err)

	endpoint := credentialsVerificationEndpoint
	didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

	verificationsHandler := getHandler(t, op, endpoint)

	t.Run("credential verification - success", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		cslBytes, err := json.Marshal(&cslstatus.CSL{})
		require.NoError(t, err)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

		vc.Status = &verifiable.TypedID{
			ID:   "http://example.com/status/100",
			Type: "CredentialStatusList2017",
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		verificationResp := &CredentialsVerificationSuccessResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 2, len(verificationResp.Checks))
	})

	t.Run("credential verification - request doesn't contain checks", func(t *testing.T) {
		req := &CredentialsVerificationRequest{
			Credential: []byte(prCardVC),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

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

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

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

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

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

		rr = serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp = &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Contains(t, verificationResp.Checks[0].Error, "verifiable credential proof validation error")
	})

	t.Run("credential verification - status check failure", func(t *testing.T) {
		t.Run("status check failure - error fetching status", func(t *testing.T) {
			vc.Status = &verifiable.TypedID{
				ID: "http://example.com/status/100",
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

			rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

			require.Equal(t, http.StatusBadRequest, rr.Code)

			verificationResp := &CredentialsVerificationFailResponse{}
			err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
			require.NoError(t, err)
			require.Equal(t, 1, len(verificationResp.Checks))
			require.Equal(t, statusCheck, verificationResp.Checks[0].Check)
			require.Contains(t, verificationResp.Checks[0].Error, "failed to fetch the status")
		})

		t.Run("status check failure - revoked", func(t *testing.T) {
			cslBytes, err := json.Marshal(&cslstatus.CSL{ID: "https://example.gov/status/24", VC: []string{
				strings.ReplaceAll(validVCStatus, "#ID", "https://issuer.oidp.uscis.gov/credentials/83627465"),
				strings.ReplaceAll(validVCStatus, "#ID", "http://example.edu/credentials/1872")}})
			require.NoError(t, err)
			op.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
				Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

			vc.Status = &verifiable.TypedID{
				ID: "http://example.com/status/100",
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

			rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

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

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		verificationResp := &CredentialsVerificationFailResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, invalidCheckName, verificationResp.Checks[0].Check)
		require.Equal(t, "check not supported", verificationResp.Checks[0].Error)
	})

	t.Run("credential verification - invalid json input", func(t *testing.T) {
		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint,
			[]byte("invalid input"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("credential verification - invalid challenge and domain", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

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

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")

		// fail when proof has challenge and no challenge in the options
		vReq = &CredentialsVerificationRequest{
			Credential: getSignedVC(t, privKey, prCardVC, didID, verificationMethod, domain, challenge),
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

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

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")
	})

	t.Run("credential verification - invalid vc proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.AssertionMethod = nil
		verificationMethod := didDoc.PublicKey[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		cslBytes, err := json.Marshal(&cslstatus.CSL{})
		require.NoError(t, err)

		ops.httpClient = &mockHTTPClient{doValue: &http.Response{StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(strings.NewReader(string(cslBytes)))}}

		vc.Status = &verifiable.TypedID{
			ID:   "http://example.com/status/100",
			Type: "CredentialStatusList2017",
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable credential proof purpose validation error :"+
			" unable to find matching assertionMethod key IDs for given verification method")
	})

	t.Run("credential verification - issuer is not the controller of verification method", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID
		vc.Issuer.ID = didDoc.ID

		ops, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, ops, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "controller of verification method doesn't match the issuer")
	})
}

func TestVerifyPresentation(t *testing.T) {
	op, err := New(&Config{
		VDRI:          &vdrimock.MockVDRIRegistry{},
		StoreProvider: memstore.NewProvider(),
	})
	require.NoError(t, err)

	endpoint := presentationsVerificationEndpoint
	verificationsHandler := getHandler(t, op, endpoint)

	t.Run("presentation verification - success", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:EiBNfNRaz1Ll8BjVsbNv-fWc7K_KIoPuW8GFCh1_Tz_Iuw=="

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusOK, rr.Code)

		verificationResp := &VerifyPresentationSuccessResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0])
	})

	t.Run("presentation verification - request doesn't contain checks", func(t *testing.T) {
		req := &VerifyPresentationRequest{
			Presentation: []byte(vpWithoutProof),
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		// verify that the default check was performed
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable presentation proof validation error : embedded proof is missing",
			verificationResp.Checks[0].Error)
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

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, proofCheck, verificationResp.Checks[0].Check)
		require.Equal(t, "verifiable presentation proof validation error : embedded proof is missing",
			verificationResp.Checks[0].Error)

		// proof validation error (DID not found)
		req = &VerifyPresentationRequest{
			Presentation: []byte(validVCWithProof),
			Opts: &VerifyPresentationOptions{
				Checks: []string{proofCheck},
			},
		}

		reqBytes, err = json.Marshal(req)
		require.NoError(t, err)

		rr = serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

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

		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint, reqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		verificationResp := &VerifyPresentationFailureResponse{}
		err = json.Unmarshal(rr.Body.Bytes(), &verificationResp)
		require.NoError(t, err)
		require.Equal(t, 1, len(verificationResp.Checks))
		require.Equal(t, invalidCheckName, verificationResp.Checks[0].Check)
		require.Equal(t, "check not supported", verificationResp.Checks[0].Error)
	})

	t.Run("presentation verification - invalid json input", func(t *testing.T) {
		rr := serveHTTP(t, verificationsHandler.Handle(), http.MethodPost, endpoint,
			[]byte("invalid input"))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Invalid request")
	})

	t.Run("presentation verification - invalid challenge and domain", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:xyz"

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

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

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")

		// fail when proof has challenge and no challenge in the options
		vReq = &VerifyPresentationRequest{
			Presentation: getSignedVP(t, privKey, prCardVC, didID, verificationMethod,
				didID, verificationMethod, domain, challenge),
		}

		vReqBytes, err = json.Marshal(vReq)
		require.NoError(t, err)

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

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

		rr = serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid domain in the proof")
	})

	t.Run("presentation verification - invalid vp proof purpose", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:xyz123"

		didDoc := createDIDDoc(didID, pubKey)
		didDoc.Authentication = nil
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

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
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "verifiable credential proof purpose validation error : unable"+
			" to find matching assertionMethod key IDs for given verification method")
	})

	t.Run("presentation verification - holder is not the controller of verification method", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didID := "did:test:abc123"

		didDoc := createDIDDoc(didID, pubKey)
		verificationMethod := didDoc.PublicKey[0].ID

		op, err := New(&Config{
			VDRI:          &vdrimock.MockVDRIRegistry{ResolveValue: didDoc},
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)

		// verify credential
		handler := getHandler(t, op, endpoint)

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

		rr := serveHTTP(t, handler.Handle(), http.MethodPost, endpoint, vReqBytes)

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
	kid := didDoc.PublicKey[0].ID

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
	verificationMethod := didDoc.PublicKey[0].ID

	vdri := &vdrimock.MockVDRIRegistry{ResolveValue: didDoc}

	// success
	doc, err := getDIDDocFromProof(verificationMethod, vdri)
	require.NoError(t, err)
	require.NotNil(t, doc)

	// fail - verification method not in correct format
	verificationMethod = "invalid-format"

	doc, err = getDIDDocFromProof(verificationMethod, vdri)
	require.Error(t, err)
	require.Contains(t, err.Error(), "verificationMethod value invalid-format should be in did#keyID format")
	require.Nil(t, doc)

	// fail - resolve error
	vdri = &vdrimock.MockVDRIRegistry{ResolveErr: errors.New("resolve error")}
	verificationMethod = didDoc.PublicKey[0].ID

	doc, err = getDIDDocFromProof(verificationMethod, vdri)
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
	vc, err := verifiable.NewUnverifiedCredential([]byte(vcJSON))
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
	})
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	signedVC, err := vc.MarshalJSON()
	require.NoError(t, err)

	return signedVC
}

func getSignedVP(t *testing.T, privKey []byte, vcJSON, holderDID, vpVerificationMethod, issuerDID, vcVerificationMethod, domain, challenge string) []byte { // nolint
	signedVC := getSignedVC(t, privKey, vcJSON, issuerDID, vcVerificationMethod, "", "")

	vc, err := verifiable.NewUnverifiedCredential(signedVC)
	require.NoError(t, err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	vp, err := vc.Presentation()
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
	})
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

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder { // nolint: unparam,lll
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
	r, err := http.NewRequest(handler.Method(), endpoint, bytes.NewBuffer(reqBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	req1 := mux.SetURLVars(r, urlVars)

	handler.Handle().ServeHTTP(rr, req1)

	return rr
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
		ServiceEndpoint: "https://agent.example.com/",
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		PublicKey:            []did.PublicKey{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.VerificationMethod{{PublicKey: signingKey}},
		Authentication:       []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityInvocation: []did.VerificationMethod{{PublicKey: signingKey}},
		CapabilityDelegation: []did.VerificationMethod{{PublicKey: signingKey}},
	}
}

const (
	prCardVC = `{
	  "@context": [
		"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1"
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
		  "https://www.w3.org/2018/credentials/v1"	
	   ],	
	   "credentialSchema":[	
	   ],	
	   "credentialStatus":{	
		  "id":"https://example.gov/status/24",	
		  "type":"CredentialStatusList2017"	
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

	validVCStatus = `{	
	  "@context": [	
		"https://www.w3.org/2018/credentials/v1"	
	  ],	
	  "credentialSchema": [],	
	  "credentialSubject": {	
		"currentStatus": "Revoked",	
		"statusReason": "Disciplinary action"	
	  },	
	  "id": "#ID",	
	  "issuanceDate": "2020-02-18T17:55:31.1381994Z",	
	  "issuer": {	
		"id": "did:example:76e12ec712ebc6f1c221ebfeb12",	
		"name": "Example University"	
	  },	
	  "type": "VerifiableCredential"	
	}`

	vpWithoutProof = `{	
		"@context": [	
			"https://www.w3.org/2018/credentials/v1",	
			"https://www.w3.org/2018/credentials/examples/v1"	
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
				"id": "https://example.gov/status/24",	
				"type": "CredentialStatusList2017"	
			}	
		}],	
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",	
		"refreshService": {	
			"id": "https://example.edu/refresh/3732",	
			"type": "ManualRefreshService2018"	
		}	
	}`
)
