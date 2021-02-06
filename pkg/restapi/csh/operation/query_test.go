package operation_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	remotecrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	remotekms "github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edge-service/pkg/client/vault"
	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation"
	models2 "github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi/models"
	edv "github.com/trustbloc/edv/pkg/client"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

func TestOperation_ReadDocQuery(t *testing.T) {
	t.Run("reads document encrypted with local KMS", func(t *testing.T) {
		t.Run("no EDV zcaps", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			agent := newAgent(t)
			jwe := encryptedJWE(t, agent, expected)

			config := agentConfig(agent)
			config.EDVClient = func(string, ...edv.Option) vault.ConfidentialStorageDocReader {
				return &mockEDVClient{doc: &models.EncryptedDocument{JWE: serializeFull(t, jwe)}}
			}

			o := newOperation(t, config)
			result, err := o.ReadDocQuery(newDocQuery())
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

			query := newDocQuery()
			query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
				BaseURL: edvURL,
				Zcap:    compress(t, marshal(t, edvZCAP)),
			}

			result, err := o.ReadDocQuery(query)
			require.NoError(t, err)

			require.Equal(t, expected, result)
		})
	})

	t.Run("reads documents encrypted with remote KMS", func(t *testing.T) {
		t.Run("no zcaps", func(t *testing.T) {
			expected := []byte(uuid.New().String())
			chs := newAgent(t)
			jwe := encryptedJWE(t, chs, expected)

			config := agentConfig(chs)
			config.EDVClient = func(url string, options ...edv.Option) vault.ConfidentialStorageDocReader {
				return edv.New(url, options...)
			}
			config.Aries.WebKMS = func(url string, c *http.Client, opts ...remotekms.Opt) *remotekms.RemoteKMS {
				return remotekms.New(url, c, opts...)
			}
			config.Aries.WebCrypto = func(url string, c *http.Client, opts ...remotekms.Opt) *remotecrypto.RemoteCrypto {
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

			query := newDocQuery()
			query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
				BaseURL: edvURL,
			}
			query.UpstreamAuth.Kms = &models2.UpstreamAuthorization{
				BaseURL: kmsURL,
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
			config.Aries.WebKMS = func(url string, c *http.Client, opts ...remotekms.Opt) *remotekms.RemoteKMS {
				return remotekms.New(url, c, opts...)
			}
			config.Aries.WebCrypto = func(url string, c *http.Client, opts ...remotekms.Opt) *remotecrypto.RemoteCrypto {
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

			query := newDocQuery()
			query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
				BaseURL: edvURL,
				Zcap:    compress(t, marshal(t, zcap)),
			}
			query.UpstreamAuth.Kms = &models2.UpstreamAuthorization{
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

		query := newDocQuery()
		query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, zcap)),
		}
		query.UpstreamAuth.Kms = &models2.UpstreamAuthorization{
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

		query := newDocQuery()
		query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, edvZCAP)),
		}
		query.UpstreamAuth.Kms = &models2.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, marshal(t, kmsZCAP)),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to determine KMS verification method: zcap does not specify a controller nor an invoker")
	})

	t.Run("fails if the zcap is malformed", func(t *testing.T) {
		chsServer := newAgent(t)

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		query := newDocQuery()
		query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    compress(t, []byte("{")),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse zcap")
	})

	t.Run("fails if the zcap is not gzipped", func(t *testing.T) {
		chsServer := newAgent(t)

		config := agentConfig(chsServer)

		o := newOperation(t, config)

		query := newDocQuery()
		query.UpstreamAuth.Edv = &models2.UpstreamAuthorization{
			BaseURL: "https://edv.example.com",
			Zcap:    base64.URLEncoding.EncodeToString([]byte("{")),
		}

		_, err := o.ReadDocQuery(query)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decompress zcap")
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
		StoreProvider: memstore.NewProvider(),
		Aries: &operation.AriesConfig{
			KMS:    agent.KMS(),
			Crypto: agent.Crypto(),
		},
		HTTPClient: &http.Client{},
	}
}

func newOperation(t *testing.T, cfg *operation.Config) *operation.Operation {
	op, err := operation.New(cfg)
	require.NoError(t, err)

	return op
}

func newDocQuery() *models2.DocQuery {
	docID := uuid.New().String()
	vaultID := uuid.New().String()

	return &models2.DocQuery{
		VaultID: &vaultID,
		DocID:   &docID,
		UpstreamAuth: &models2.DocQueryAO1UpstreamAuth{
			Edv: &models2.UpstreamAuthorization{
				BaseURL: "https://edv.example.com",
			},
		},
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

type mockEDVClient struct {
	doc *models.EncryptedDocument
	err error
}

func (m *mockEDVClient) ReadDocument(string, string, ...edv.ReqOption) (*models.EncryptedDocument, error) {
	return m.doc, m.err
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
		zcapld.WithInvocationTarget(uuid.New().String(), "urn:confidentialstoragehub:profile"),
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

func unwrapKey(t *testing.T, keyID string, kms kms.KeyManager, c crypto.Crypto, request *unwrapRequest) []byte {
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

	kh, err := kms.Get(keyID)
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
