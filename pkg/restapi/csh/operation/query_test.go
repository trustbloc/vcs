/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	remotecrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	edv "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"

	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
	zcapld2 "github.com/trustbloc/edge-service/pkg/restapi/csh/operation/zcapld"
)

func TestOperation_ReadDocQuery(t *testing.T) {
	t.Run("reads document encrypted with local KMS", func(t *testing.T) {
		t.Run("no EDV zcaps", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			agent := newAgent(t)
			jwe := encryptedJWE(t, agent, expected)

			config := agentConfig(agent)
			config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
				return newMockEDVClient(t, nil, jwe)
			}
			config.Aries.WebKMS = func(url string, c webkms.HTTPClient, opts ...webkms.Opt) kms.KeyManager {
				return webkms.New(url, c, opts...)
			}
			config.Aries.WebCrypto = func(url string, c remotecrypto.HTTPClient, opts ...webkms.Opt) crypto.Crypto {
				return remotecrypto.New(url, c, opts...)
			}

			kmsURL := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				request := &unwrapRequest{}
				err := json.NewDecoder(r.Body).Decode(request)
				require.NoError(t, err)

				cek := unwrapKey(t, keyID(r.URL.Path), agent.KMS(), agent.Crypto(), request)

				err = json.NewEncoder(w).Encode(&unwrapResp{Key: base64.URLEncoding.EncodeToString(cek)})
				require.NoError(t, err)
			})

			invoker := newVerMethod(t, agent.KMS())
			query := newDocQuery(t)
			query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
				BaseURL: kmsURL,
				Zcap: compress(t, marshal(t, &zcapld.Capability{
					Invoker: invoker,
					InvocationTarget: zcapld.InvocationTarget{
						ID: "/kms/keystores/abc",
					},
				})),
			}

			o := newOperation(t, config)
			result, err := o.ReadDocQuery(query)
			require.NoError(t, err)
			require.Equal(t, expected, result)
		})

		t.Run("with EDV zcaps", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			edvServer := newAgent(t)
			chs := newAgent(t)
			jwe := encryptedJWE(t, chs, expected)

			config := agentConfig(chs)
			config.EDVClient = func(url string, options ...edv.Option) vault.ConfidentialStorageDocReader {
				return edv.New(url, options...)
			}
			o := newOperation(t, config)

			edvURL := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				require.NotEmpty(t, r.Header.Get("capability-invocation"))
				require.NotEmpty(t, r.Header.Get("signature"))

				_, err := w.Write(marshal(t, &models.EncryptedDocument{JWE: serializeFull(t, jwe)}))
				require.NoError(t, err)
			})

			edvZCAP := newZCAP(t, edvServer, chs)

			query := docQuery(&openapi.UpstreamAuthorization{
				BaseURL: edvURL,
				Zcap:    compress(t, marshal(t, edvZCAP)),
			}, nil)

			result, err := o.ReadDocQuery(query)
			require.NoError(t, err)

			require.Equal(t, expected, result)
		})
	})

	t.Run("reads documents encrypted with remote KMS", func(t *testing.T) {
		t.Run("no zcaps", func(t *testing.T) {
			t.Skip("TODO - to be re-enabled once remote KMS zcaps are made optional again")
			expected := randomDoc(t)
			chs := newAgent(t)
			jwe := encryptedJWE(t, chs, expected)

			config := agentConfig(chs)
			config.EDVClient = func(url string, options ...edv.Option) vault.ConfidentialStorageDocReader {
				return edv.New(url, options...)
			}
			config.Aries.WebKMS = func(url string, c webkms.HTTPClient, opts ...webkms.Opt) kms.KeyManager {
				return webkms.New(url, c, opts...)
			}
			config.Aries.WebCrypto = func(url string, c remotecrypto.HTTPClient, opts ...webkms.Opt) crypto.Crypto {
				return remotecrypto.New(url, c, opts...)
			}
			o := newOperation(t, config)

			edvURL := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(marshal(t, &models.EncryptedDocument{JWE: serializeFull(t, jwe)}))
				require.NoError(t, err)
			})

			kmsURL := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.String(), "unwrap") {
					request := &unwrapRequest{}
					err := json.NewDecoder(r.Body).Decode(request)
					require.NoError(t, err)

					cek := unwrapKey(t, keyID(r.URL.Path), chs.KMS(), chs.Crypto(), request)

					err = json.NewEncoder(w).Encode(&unwrapResp{Key: base64.URLEncoding.EncodeToString(cek)})
					require.NoError(t, err)

					return
				}
			})

			invoker := newVerMethod(t, chs.KMS())

			query := newDocQuery(t)
			query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
				BaseURL: edvURL,
			}
			query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
				BaseURL: kmsURL,
				Zcap: compress(t, marshal(t, &zcapld.Capability{
					InvocationTarget: zcapld.InvocationTarget{
						ID: "/kms/keystores/abc",
					},
					Invoker: invoker,
				})),
			}

			result, err := o.ReadDocQuery(query)
			require.NoError(t, err)

			require.Equal(t, expected, result)
		})

		t.Run("with zcaps", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			edvServer := newAgent(t)
			chs := newAgent(t)
			jwe := encryptedJWE(t, chs, expected)

			config := agentConfig(chs)
			config.EDVClient = func(url string, options ...edv.Option) vault.ConfidentialStorageDocReader {
				return edv.New(url, options...)
			}
			config.Aries.WebKMS = func(url string, c webkms.HTTPClient, opts ...webkms.Opt) kms.KeyManager {
				return webkms.New(url, c, opts...)
			}
			config.Aries.WebCrypto = func(url string, c remotecrypto.HTTPClient, opts ...webkms.Opt) crypto.Crypto {
				return remotecrypto.New(url, c, opts...)
			}
			o := newOperation(t, config)

			edvURL := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				checkZCAPHeaders(t, r)

				_, err := w.Write(marshal(t, &models.EncryptedDocument{JWE: serializeFull(t, jwe)}))
				require.NoError(t, err)
			})

			kmsURL := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				checkZCAPHeaders(t, r)

				if strings.HasSuffix(r.URL.String(), "unwrap") {
					request := &unwrapRequest{}
					err := json.NewDecoder(r.Body).Decode(request)
					require.NoError(t, err)

					cek := unwrapKey(t, keyID(r.URL.Path), chs.KMS(), chs.Crypto(), request)

					err = json.NewEncoder(w).Encode(&unwrapResp{Key: base64.URLEncoding.EncodeToString(cek)})
					require.NoError(t, err)

					return
				}
			})

			zcap := newZCAP(t, edvServer, chs)

			query := newDocQuery(t)
			query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
				BaseURL: edvURL,
				Zcap:    compress(t, marshal(t, zcap)),
			}
			query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
				BaseURL: kmsURL,
				Zcap:    compress(t, marshal(t, zcap)),
			}

			result, err := o.ReadDocQuery(query)
			require.NoError(t, err)

			require.Equal(t, expected, result)
		})
	})

	t.Run("fails if EDV zcap does not have an invoker nor controller", func(t *testing.T) {
		chsServer := newAgent(t)
		edvServer := newAgent(t)
		zcap := newZCAP(t, edvServer, chsServer)
		zcap.Invoker = ""
		zcap.Controller = ""

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		query := newDocQuery(t)
		query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, zcap)),
		}
		query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, zcap)),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to determine EDV verification method: zcap does not specify a controller nor an invoker")
	})

	t.Run("fails if KMS zcap does not have an invoker nor controller", func(t *testing.T) {
		chsServer := newAgent(t)
		edvServer := newAgent(t)
		edvZCAP := newZCAP(t, edvServer, chsServer)
		kmsZCAP := newZCAP(t, edvServer, chsServer)
		kmsZCAP.Invoker = ""
		kmsZCAP.Controller = ""

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		query := newDocQuery(t)
		query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, edvZCAP)),
		}
		query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, kmsZCAP)),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to determine KMS verification method: zcap does not specify a controller nor an invoker")
	})

	t.Run("fails if the EDV zcap is malformed", func(t *testing.T) {
		chsServer := newAgent(t)

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		query := newDocQuery(t)
		query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, []byte("{")),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse zcap")
	})

	t.Run("fails if the EDV zcap is not gzipped", func(t *testing.T) {
		chsServer := newAgent(t)

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		query := newDocQuery(t)
		query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    base64.URLEncoding.EncodeToString([]byte("{")),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse zcap: failed to init gzip reader: unexpected EOF")
	})

	t.Run("fails if the KMS zcap is malformed", func(t *testing.T) {
		chsServer := newAgent(t)
		edvServer := newAgent(t)

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		edvZCAP := newZCAP(t, edvServer, chsServer)

		query := newDocQuery(t)
		query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, edvZCAP)),
		}
		query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
			BaseURL: "https://kms.example.com",
			Zcap:    "INVALID",
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse zcap: failed to base64URL-decode value INVALID")
	})

	t.Run("fails if the KMS zcap has a malformed invocation target ID", func(t *testing.T) {
		chsServer := newAgent(t)
		edvServer := newAgent(t)

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		edvZCAP := newZCAP(t, edvServer, chsServer)
		kmsZCAP := newZCAP(t, edvServer, chsServer)
		kmsZCAP.InvocationTarget.ID = "%"

		query := newDocQuery(t)
		query.UpstreamAuth.Edv = &openapi.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, edvZCAP)),
		}
		query.UpstreamAuth.Kms = &openapi.UpstreamAuthorization{
			BaseURL: "https://kms.example.com",
			Zcap:    compress(t, marshal(t, kmsZCAP)),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse zcap invocation target id")
	})
}

func newServer(t *testing.T, handlerFunc http.HandlerFunc) string {
	t.Helper()

	srv := httptest.NewServer(&handler{h: handlerFunc})

	t.Cleanup(srv.Close)

	return srv.URL
}

type handler struct {
	h http.HandlerFunc
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.h(w, r)
}

func agentConfig(agent *context.Provider) *operation.Config {
	return &operation.Config{
		StoreProvider: mem.NewProvider(),
		Aries: &operation.AriesConfig{
			KMS:          agent.KMS(),
			Crypto:       agent.Crypto(),
			DIDResolvers: []zcapld2.DIDResolver{key.New()},
			PublicDIDCreator: func(kms.KeyManager) (*did.DocResolution, error) {
				return &did.DocResolution{
					DIDDocument: &did.Doc{
						ID:      "did:example:123",
						Context: []string{did.Context},
						Authentication: []did.Verification{{
							VerificationMethod: did.VerificationMethod{
								ID:    uuid.New().String() + "#key1",
								Type:  "JsonWebKey2020",
								Value: []byte(uuid.New().String()),
							},
							Relationship: did.Authentication,
							Embedded:     true,
						}},
						CapabilityDelegation: []did.Verification{{
							VerificationMethod: did.VerificationMethod{
								ID:    uuid.New().String() + "#key2",
								Type:  "JsonWebKey2020",
								Value: []byte(uuid.New().String()),
							},
							Relationship: did.CapabilityDelegation,
							Embedded:     true,
						}},
						CapabilityInvocation: []did.Verification{{
							VerificationMethod: did.VerificationMethod{
								ID:    uuid.New().String() + "#key2",
								Type:  "JsonWebKey2020",
								Value: []byte(uuid.New().String()),
							},
							Relationship: did.CapabilityInvocation,
							Embedded:     true,
						}},
					},
				}, nil
			},
		},
		HTTPClient: &http.Client{},
	}
}

func newOperation(t *testing.T, cfg *operation.Config) *operation.Operation {
	op, err := operation.New(cfg)
	require.NoError(t, err)

	return op
}

func newDocQuery(t *testing.T) *openapi.DocQuery {
	docID := uuid.New().String()
	vaultID := uuid.New().String()

	query := &openapi.DocQuery{
		VaultID: &vaultID,
		DocID:   &docID,
		UpstreamAuth: &openapi.DocQueryAO1UpstreamAuth{
			Edv: &openapi.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			},
			Kms: &openapi.UpstreamAuthorization{
				BaseURL: "https://kms.example.com",
				Zcap: compress(t, marshal(t, &zcapld.Capability{
					InvocationTarget: zcapld.InvocationTarget{
						ID: "https://kms.example.com/kms/keystores/abc",
					},
				})),
			},
		},
	}

	return query
}

func docQuery(edvAuth, kmsAuth *openapi.UpstreamAuthorization) *openapi.DocQuery {
	docID := uuid.New().String()
	vaultID := uuid.New().String()

	query := &openapi.DocQuery{
		VaultID: &vaultID,
		DocID:   &docID,
		UpstreamAuth: &openapi.DocQueryAO1UpstreamAuth{
			Edv: edvAuth,
			Kms: kmsAuth,
		},
	}

	return query
}

func refQuery(ref string) *openapi.RefQuery {
	return &openapi.RefQuery{
		Ref: &ref,
	}
}

func encryptedJWE(t *testing.T, agent *context.Provider, msg []byte) *jose.JSONWebEncryption {
	_, rawPubKey, err := agent.KMS().CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
	require.NoError(t, err)

	recipientKey := &crypto.PublicKey{}
	err = json.Unmarshal(rawPubKey, recipientKey)
	require.NoError(t, err)

	jweEncrpt, err := jose.NewJWEEncrypt(
		jose.A256GCM,
		"",
		"",
		"",
		nil,
		[]*crypto.PublicKey{recipientKey},
		agent.Crypto(),
	)
	require.NoError(t, err)

	jwe, err := jweEncrpt.Encrypt(msg)
	require.NoError(t, err)

	return jwe
}

func serializeFull(t *testing.T, jwe *jose.JSONWebEncryption) []byte {
	t.Helper()

	s, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)

	return []byte(s)
}

func newAgent(t *testing.T) *context.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}

func newVerMethod(t *testing.T, k kms.KeyManager) string {
	_, pubKeyBytes, err := k.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func newMockEDVClient(t *testing.T, err error, docs ...*jose.JSONWebEncryption) *mockEDVClient {
	edvDocs := make([]*models.EncryptedDocument, len(docs))

	for i := range docs {
		edvDocs[i] = &models.EncryptedDocument{JWE: serializeFull(t, docs[i])}
	}

	return &mockEDVClient{
		docs: edvDocs,
		err:  err,
	}
}

type mockEDVClient struct {
	docs []*models.EncryptedDocument
	err  error
}

func (m *mockEDVClient) ReadDocument(string, string, ...edv.ReqOption) (*models.EncryptedDocument, error) {
	if m.err != nil {
		return nil, m.err
	}

	if len(m.docs) == 0 {
		return nil, fmt.Errorf("docs exhausted")
	}

	doc := m.docs[0]
	m.docs = m.docs[1:]

	return doc, nil
}

func newZCAP(t *testing.T, server, rp *context.Provider) *zcapld.Capability {
	t.Helper()

	_, pubKeyBytes, err := rp.KMS().CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invoker := didKeyURL(pubKeyBytes)

	signer, err := signature.NewCryptoSigner(server.Crypto(), server.KMS(), kms.ED25519Type)
	require.NoError(t, err)

	verificationMethod := didKeyURL(signer.PublicKeyBytes())

	zcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: verificationMethod,
		},
		zcapld.WithID(uuid.New().String()),
		zcapld.WithInvoker(invoker),
		zcapld.WithController(invoker),
		zcapld.WithInvocationTarget(
			fmt.Sprintf("https://kms.example.com/kms/keystores/%s", uuid.New().String()),
			"urn:confidentialstoragehub:profile",
		),
	)
	require.NoError(t, err)

	return zcap
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

func unmarshal(t *testing.T, v interface{}, raw []byte) {
	t.Helper()

	err := json.NewDecoder(bytes.NewReader(raw)).Decode(v)
	require.NoError(t, err)
}

func compress(t *testing.T, msg []byte) string {
	t.Helper()

	compressed := bytes.NewBuffer(nil)
	compressor := gzip.NewWriter(compressed)

	_, err := compressor.Write(msg)
	require.NoError(t, err)

	err = compressor.Close()
	require.NoError(t, err)

	return base64.URLEncoding.EncodeToString(compressed.Bytes())
}

type unwrapRequest struct {
	WrappedKey struct {
		KID          string    `json:"kid,omitempty"`
		EncryptedCEK string    `json:"encryptedCEK,omitempty"`
		EPK          publicKey `json:"epk,omitempty"`
		Alg          string    `json:"alg,omitempty"`
		APU          string    `json:"apu,omitempty"`
		APV          string    `json:"apv,omitempty"`
	} `json:"wrappedKey,omitempty"`
	SenderKID string `json:"senderKID,omitempty"`
}

type unwrapResp struct {
	Key string `json:"key,omitempty"`
}

type publicKey struct {
	KID   string `json:"kid,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

func unwrapKey(t *testing.T, keyID string, km kms.KeyManager, c crypto.Crypto, request *unwrapRequest) []byte {
	kid, err := base64.URLEncoding.DecodeString(request.WrappedKey.KID)
	require.NoError(t, err)

	enc, err := base64.URLEncoding.DecodeString(request.WrappedKey.EncryptedCEK)
	require.NoError(t, err)

	epk := unmarshalPublicKey(t, &request.WrappedKey.EPK)

	alg, err := base64.URLEncoding.DecodeString(request.WrappedKey.Alg)
	require.NoError(t, err)

	apu, err := base64.URLEncoding.DecodeString(request.WrappedKey.APU)
	require.NoError(t, err)

	apv, err := base64.URLEncoding.DecodeString(request.WrappedKey.APV)
	require.NoError(t, err)

	recipientWK := &crypto.RecipientWrappedKey{
		KID:          string(kid),
		EncryptedCEK: enc,
		EPK:          *epk,
		Alg:          string(alg),
		APU:          apu,
		APV:          apv,
	}

	kh, err := km.Get(keyID)
	require.NoError(t, err)

	cek, err := c.UnwrapKey(recipientWK, kh)
	require.NoError(t, err)

	return cek
}

func unmarshalPublicKey(t *testing.T, k *publicKey) *crypto.PublicKey {
	kid, err := base64.URLEncoding.DecodeString(k.KID)
	require.NoError(t, err)

	x, err := base64.URLEncoding.DecodeString(k.X)
	require.NoError(t, err)

	y, err := base64.URLEncoding.DecodeString(k.Y)
	require.NoError(t, err)

	curve, err := base64.URLEncoding.DecodeString(k.Curve)
	require.NoError(t, err)

	typ, err := base64.URLEncoding.DecodeString(k.Type)
	require.NoError(t, err)

	return &crypto.PublicKey{
		KID:   string(kid),
		X:     x,
		Y:     y,
		Curve: string(curve),
		Type:  string(typ),
	}
}

func keyID(path string) string {
	// full path: /kms/keystores/{keystoreID}/keys/{keyID}/unwrap
	id := strings.Replace(path, "/unwrap", "", 1)

	return id[strings.LastIndex(id, "/")+1:]
}

func checkZCAPHeaders(t *testing.T, r *http.Request) {
	require.NotEmpty(t, r.Header.Get("capability-invocation"))
	require.NotEmpty(t, r.Header.Get("signature"))
}
