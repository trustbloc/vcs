/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"github.com/trustbloc/edv/pkg/restapi/messages"

	. "github.com/trustbloc/edge-service/pkg/restapi/vault"
)

const kmsResponse = `
{
   "wrappedKey":{
      "kid":"R0tzelREUWNXckZsTVMtQk83LWFzZk5nYUZmTVo5NnQ2ZWVUaklfX1kxYw==",
      "encryptedCEK":"5es-1SkzIwvKnM1suaYLrNnXzzUTMG28Ow5cDKCsK_yUBiCqlvtDmw==",
      "epk":{
         "x":"f9ccLKPnZcFwW1BroF56M1XTUG5GSYrXLAPLsi-OFsI=",
         "y":"aqdkBFWEUZ0RWa9p4W66gPd37oe2s26gypmHZ_P0eUU=",
         "curve":"UC0yNTY=",
         "type":"RUM="
      },
      "alg":"RUNESC1FUytBMjU2S1c="
   }
}`

func TestNewClient(t *testing.T) {
	t.Run("URL parse error", func(t *testing.T) {
		client, err := NewClient("", "http://user^foo.com", nil, nil)
		require.Error(t, err)
		require.Nil(t, client)
		require.Contains(t, err.Error(), "url parse: parse")
	})
	t.Run("URL parse error", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("test"),
		})
		require.Error(t, err)
		require.Nil(t, client)
		require.EqualError(t, err, "open store: test")
	})
}

func TestClient_CreateVault(t *testing.T) {
	t.Run("Error parse zcap", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write([]byte(`[]`))
			require.NoError(t, err)
		}))

		store := mem.NewProvider()
		client, err := NewClient(remoteKMS.URL, edv.URL, newLocalKms(t, store), store)
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse capability: failed to unmarshal zcap")
	})

	t.Run("KMS bad URL", func(t *testing.T) {
		store := mem.NewProvider()
		client, err := NewClient("http://user^foo.com", "", newLocalKms(t, store), store)
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key store: build request for Create keystore error")
	})

	t.Run("KMS create key store error", func(t *testing.T) {
		store := mem.NewProvider()
		client, err := NewClient("", "",
			newLocalKms(t, store), store,
			WithHTTPClient(&http.Client{}),
		)
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key store: posting Create keystore failed")
	})

	t.Run("EDV error", func(t *testing.T) {
		store := mem.NewProvider()
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))

		client, err := NewClient(remoteKMS.URL, edv.URL, newLocalKms(t, store), store)
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "the EDV server returned status code 400")
	})

	t.Run("Save authorization error", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0b9em5ioud57602s7og")
			w.Header().Set("X-ROOTCAPABILITY", "H4sIAAAAAAAA_5SSS3OjOBSF_8vt5ZAY8AOs1fiBE-LYhEDHga4ul4wULF4ikrAhqfz3KcdxL2bVWfFRdW4d3XPuO_yb8ErRVgGCvVK1RL3esc_INRdpT9KkEUx1vYMJGjACCHp5KXs57aTigspeou_GtBwy3pChNdJNafH0JK0OPKcCEBBGUE479DZa5a951ZGsiukofn1e3ziHLAof2mP5822SvwWGdT-5C5tIrnzZiR_fHQANcFHwIyWTRDFeAfoFiaBY0SXtQAPa1lyoM0uWVqDBgQr2cvo_ClyDBk31BQkv60bR1WT2R3VmWiWiqxVoQOiFmppgRZ350wzXeMcKpj7tsLx8vJqe3CTFxSf-PueT4NMzQyxSqgC9gzv_63jDrqaAoBEVykuJLnr40KAWnL8A-vX-tfypM1M3jSvduOobodFHAwMZ5rU1tAf20DTMf3QT6TpokB0lIKDd3X53kzCP3S1i5zH0A1e6pWuuZ-4oLhcyMX9Kt1x3-NlnXiFZlEW6Wxjj62ujHOZr7Ja7m2c7nT4MNvOGL5WzXSuRkg2RwTLbhtvcC3dzj-I9JtvNON0_tYNVvFkEzzOGsXf3ZlnjdExuX9vofvCoT3zQoOJVclr3celOR0VQzLb2yH1alF5nK8uyjiz37JSNkix4HQ-UT62t8l8qZ8mUzGpxu7ufBk5ylbrjjdVv4sWSvFQ0cpxFNDpOxQS-MntoRM3lySf50-OcFjT9rAk0UOfQHWIOh8Y4YGmFVSOoqRv25UrYudMVVXtO_nf8h9u970dtsG-btj9VEZkZ94_TDV-bmd1ZflyZ093DNMOxPaA_vjsAH78__gsAAP__CIjUdMsDAAA=") // nolint: lll

			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write([]byte(`{"@context":"https://w3id.org/security/v2","id":"urn:uuid:293817e5-3a47-4685-9bd3-51eba3d5e928","invoker":"did:key:z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr#z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr","parentCapability":"urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14","allowedAction":["read","write"],"invocationTarget":{"ID":"DWPPbEVn1afJY4We3kpQmq","Type":"urn:edv:vault"},"proof":[{"capabilityChain":["urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14"],"created":"2021-01-31T13:41:13.863452194+02:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..NfznOmAi16H7fXJ1lI3-JzzHlOMopAhdGnBaF_FYK_F5BHbJMpH0u1aZ_JMgrG2XHUFMLNCBxG91DA-tJn2gDQ","nonce":"ZjtzLnBIpSNLteskV4bgTI8LOwrqrETpDI31qPglCNT_V-78ZmChHhqksMEu59WhkA_hofadF8saneziAhCDRA","proofPurpose":"capabilityDelegation","type":"Ed25519Signature2018","verificationMethod":"did:key:z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn#z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn"}]}`)) // nolint: lll
			require.NoError(t, err)
		}))

		store := mem.NewProvider()
		client, err := NewClient(remoteKMS.URL, edv.URL, newLocalKms(t, store), &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{ErrPut: errors.New("test")},
		})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.EqualError(t, err, "save vault info: test")
	})

	t.Run("Create vault", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0b9em5ioud57602s7og")
			w.Header().Set("X-ROOTCAPABILITY", "H4sIAAAAAAAA_5SSS3OjOBSF_8vt5ZAY8AOs1fiBE-LYhEDHga4ul4wULF4ikrAhqfz3KcdxL2bVWfFRdW4d3XPuO_yb8ErRVgGCvVK1RL3esc_INRdpT9KkEUx1vYMJGjACCHp5KXs57aTigspeou_GtBwy3pChNdJNafH0JK0OPKcCEBBGUE479DZa5a951ZGsiukofn1e3ziHLAof2mP5822SvwWGdT-5C5tIrnzZiR_fHQANcFHwIyWTRDFeAfoFiaBY0SXtQAPa1lyoM0uWVqDBgQr2cvo_ClyDBk31BQkv60bR1WT2R3VmWiWiqxVoQOiFmppgRZ350wzXeMcKpj7tsLx8vJqe3CTFxSf-PueT4NMzQyxSqgC9gzv_63jDrqaAoBEVykuJLnr40KAWnL8A-vX-tfypM1M3jSvduOobodFHAwMZ5rU1tAf20DTMf3QT6TpokB0lIKDd3X53kzCP3S1i5zH0A1e6pWuuZ-4oLhcyMX9Kt1x3-NlnXiFZlEW6Wxjj62ujHOZr7Ja7m2c7nT4MNvOGL5WzXSuRkg2RwTLbhtvcC3dzj-I9JtvNON0_tYNVvFkEzzOGsXf3ZlnjdExuX9vofvCoT3zQoOJVclr3celOR0VQzLb2yH1alF5nK8uyjiz37JSNkix4HQ-UT62t8l8qZ8mUzGpxu7ufBk5ylbrjjdVv4sWSvFQ0cpxFNDpOxQS-MntoRM3lySf50-OcFjT9rAk0UOfQHWIOh8Y4YGmFVSOoqRv25UrYudMVVXtO_nf8h9u970dtsG-btj9VEZkZ94_TDV-bmd1ZflyZ093DNMOxPaA_vjsAH78__gsAAP__CIjUdMsDAAA=") // nolint: lll

			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write([]byte(`{"@context":"https://w3id.org/security/v2","id":"urn:uuid:293817e5-3a47-4685-9bd3-51eba3d5e928","invoker":"did:key:z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr#z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr","parentCapability":"urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14","allowedAction":["read","write"],"invocationTarget":{"ID":"DWPPbEVn1afJY4We3kpQmq","Type":"urn:edv:vault"},"proof":[{"capabilityChain":["urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14"],"created":"2021-01-31T13:41:13.863452194+02:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..NfznOmAi16H7fXJ1lI3-JzzHlOMopAhdGnBaF_FYK_F5BHbJMpH0u1aZ_JMgrG2XHUFMLNCBxG91DA-tJn2gDQ","nonce":"ZjtzLnBIpSNLteskV4bgTI8LOwrqrETpDI31qPglCNT_V-78ZmChHhqksMEu59WhkA_hofadF8saneziAhCDRA","proofPurpose":"capabilityDelegation","type":"Ed25519Signature2018","verificationMethod":"did:key:z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn#z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn"}]}`)) // nolint: lll
			require.NoError(t, err)
		}))

		store := mem.NewProvider()
		client, err := NewClient(remoteKMS.URL, edv.URL, newLocalKms(t, store), store)
		require.NoError(t, err)

		result, err := client.CreateVault()
		require.NoError(t, err)
		require.NotEmpty(t, result.ID)
		require.NotEmpty(t, result.EDV.URI)
		require.NotEmpty(t, result.EDV.AuthToken)
		require.NotEmpty(t, result.KMS.URI)
		require.NotEmpty(t, result.KMS.AuthToken)
	})
}

func TestClient_GetAuthorization(t *testing.T) {
	t.Run("No authorization", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{},
		})
		require.NoError(t, err)

		_, err = client.GetAuthorization("", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get: data not found")
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					"authorization_vid_id": {Value: []byte(`{`)},
				},
			},
		})
		require.NoError(t, err)

		_, err = client.GetAuthorization("vid", "id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal: unexpected end of JSON input")
	})

	t.Run("Success", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					"authorization_vid_id": {Value: []byte(`{}`)},
				},
			},
		})
		require.NoError(t, err)

		res, err := client.GetAuthorization("vid", "id")
		require.NoError(t, err)
		require.NotNil(t, res)
	})
}

func TestClient_SaveDoc(t *testing.T) { // nolint: gocyclo
	const (
		docID   = "id"
		vaultID = "v_id"
	)

	t.Run("Unmarshal authorization error", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					"info_v_id": {Value: []byte(`{`)},
				},
			},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vault info: unmarshal")
	})
	t.Run("No authorization", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vault info: get: data not found")
	})

	t.Run("Create meta doc info (error)", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		kmsHandlers := make(chan func(w http.ResponseWriter, r *http.Request), 3)
		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0ekinlioud42c84qs7g/keys/GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c")

			w.WriteHeader(http.StatusCreated)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload, err := json.Marshal(map[string][]byte{"publicKey": []byte(`{"kid":"GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c","x":"IM1/HfveJ4rbqAYzBOmVOnpys4h3J0yA3I238AjYzZc=","y":"S+h2S7IbWCZiQjOaNIhSvyqNcRnRKavdiC1BU8F2UU4=","curve":"NIST_P256","type":"EC"}`)}) // nolint: lll
			require.NoError(t, err)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err = w.Write(payload)
			require.NoError(t, err)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload := []byte(kmsResponse)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write(payload)
			require.NoError(t, err)

			store.Store.ErrPut = errors.New("text")
		}

		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case fn := <-kmsHandlers:
				fn(w, r)
			default:
				t.Error("no handler")
			}
		}))

		lKMS := newLocalKms(t, store)
		client, err := NewClient(remoteKMS.URL, "", lKMS, store)
		require.NoError(t, err)

		vID, dURL, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "auth":{"edv":{},"kms":{"uri":"/"}}}`),
		}

		_, err = client.SaveDoc(vID, docID, data["info_"+vID].Value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create meta doc info: store put: text")
	})

	t.Run("Encrypt key (create error)", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					"info_v_id": {Value: []byte(`{"auth":{"edv":{},"kms":{}}}`)},
				},
			},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, []byte(`{"auth":{"edv":{},"kms":{}}}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "encrypt key: create: posting Create key failed")
	})

	t.Run("Get meta doc info (error)", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		kmsHandlers := make(chan func(w http.ResponseWriter, r *http.Request), 3)
		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0ekinlioud42c84qs7g/keys/GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c")

			w.WriteHeader(http.StatusCreated)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload, err := json.Marshal(map[string][]byte{"publicKey": []byte(`{"kid":"GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c","x":"IM1/HfveJ4rbqAYzBOmVOnpys4h3J0yA3I238AjYzZc=","y":"S+h2S7IbWCZiQjOaNIhSvyqNcRnRKavdiC1BU8F2UU4=","curve":"NIST_P256","type":"EC"}`)}) // nolint: lll
			require.NoError(t, err)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err = w.Write(payload)
			require.NoError(t, err)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload := []byte(kmsResponse)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write(payload)
			require.NoError(t, err)

			store.Store.ErrGet = errors.New("text")
		}

		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case fn := <-kmsHandlers:
				fn(w, r)
			default:
				t.Error("no handler")
			}
		}))

		lKMS := newLocalKms(t, store)
		client, err := NewClient(remoteKMS.URL, "", lKMS, store)
		require.NoError(t, err)

		vID, dURL, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "auth":{"edv":{},"kms":{"uri":"/"}}}`),
		}

		_, err = client.SaveDoc(vID, docID, data["info_"+vID].Value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get meta doc info: store get: text")
	})

	t.Run("Encrypt key (create error)", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					"info_v_id": {Value: []byte(`{"auth":{"edv":{},"kms":{}}}`)},
				},
			},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, []byte(`{"auth":{"edv":{},"kms":{}}}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "encrypt key: create: posting Create key failed")
	})

	t.Run("Success save", func(t *testing.T) {
		kmsHandlers := make(chan func(w http.ResponseWriter, r *http.Request), 3)
		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0ekinlioud42c84qs7g/keys/GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c")

			w.WriteHeader(http.StatusCreated)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload, err := json.Marshal(map[string][]byte{"publicKey": []byte(`{"kid":"GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c","x":"IM1/HfveJ4rbqAYzBOmVOnpys4h3J0yA3I238AjYzZc=","y":"S+h2S7IbWCZiQjOaNIhSvyqNcRnRKavdiC1BU8F2UU4=","curve":"NIST_P256","type":"EC"}`)}) // nolint: lll
			require.NoError(t, err)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err = w.Write(payload)
			require.NoError(t, err)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload := []byte(kmsResponse)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write(payload)
			require.NoError(t, err)
		}

		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case fn := <-kmsHandlers:
				fn(w, r)
			default:
				t.Error("no handler")
			}
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write([]byte(`{"@context":"https://w3id.org/security/v2","id":"urn:uuid:293817e5-3a47-4685-9bd3-51eba3d5e928","invoker":"did:key:z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr#z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr","parentCapability":"urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14","allowedAction":["read","write"],"invocationTarget":{"ID":"DWPPbEVn1afJY4We3kpQmq","Type":"urn:edv:vault"},"proof":[{"capabilityChain":["urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14"],"created":"2021-01-31T13:41:13.863452194+02:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..NfznOmAi16H7fXJ1lI3-JzzHlOMopAhdGnBaF_FYK_F5BHbJMpH0u1aZ_JMgrG2XHUFMLNCBxG91DA-tJn2gDQ","nonce":"ZjtzLnBIpSNLteskV4bgTI8LOwrqrETpDI31qPglCNT_V-78ZmChHhqksMEu59WhkA_hofadF8saneziAhCDRA","proofPurpose":"capabilityDelegation","type":"Ed25519Signature2018","verificationMethod":"did:key:z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn#z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn"}]}`)) // nolint: lll
			require.NoError(t, err)
		}))

		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient(remoteKMS.URL, edv.URL, lKMS, store)
		require.NoError(t, err)

		vID, dURL, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "auth":{"edv":{},"kms":{"uri":"/"}}}`),
		}

		docMeta, err := client.SaveDoc(vID, docID, data["info_"+vID].Value)
		require.NoError(t, err)
		require.NotEmpty(t, docMeta.ID)
		require.NotEmpty(t, docMeta.URI)
	})

	t.Run("Success (update)", func(t *testing.T) {
		kmsHandlers := make(chan func(w http.ResponseWriter, r *http.Request), 3)
		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/kms/keystores/c0ekinlioud42c84qs7g/keys/GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c")

			w.WriteHeader(http.StatusCreated)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload, err := json.Marshal(map[string][]byte{"publicKey": []byte(`{"kid":"GKszTDQcWrFlMS-BO7-asfNgaFfMZ96t6eeTjI__Y1c","x":"IM1/HfveJ4rbqAYzBOmVOnpys4h3J0yA3I238AjYzZc=","y":"S+h2S7IbWCZiQjOaNIhSvyqNcRnRKavdiC1BU8F2UU4=","curve":"NIST_P256","type":"EC"}`)}) // nolint: lll
			require.NoError(t, err)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err = w.Write(payload)
			require.NoError(t, err)
		}

		kmsHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			payload := []byte(kmsResponse)

			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write(payload)
			require.NoError(t, err)
		}

		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case fn := <-kmsHandlers:
				fn(w, r)
			default:
				t.Error("no handler")
			}
		}))

		edvHandlers := make(chan func(w http.ResponseWriter, r *http.Request), 2)
		edvHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusConflict)

			_, err := w.Write([]byte(messages.ErrDuplicateDocument.Error() + "."))
			require.NoError(t, err)
		}

		edvHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusOK)

			_, err := w.Write([]byte(`{"@context":"https://w3id.org/security/v2","id":"urn:uuid:293817e5-3a47-4685-9bd3-51eba3d5e928","invoker":"did:key:z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr#z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr","parentCapability":"urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14","allowedAction":["read","write"],"invocationTarget":{"ID":"DWPPbEVn1afJY4We3kpQmq","Type":"urn:edv:vault"},"proof":[{"capabilityChain":["urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14"],"created":"2021-01-31T13:41:13.863452194+02:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..NfznOmAi16H7fXJ1lI3-JzzHlOMopAhdGnBaF_FYK_F5BHbJMpH0u1aZ_JMgrG2XHUFMLNCBxG91DA-tJn2gDQ","nonce":"ZjtzLnBIpSNLteskV4bgTI8LOwrqrETpDI31qPglCNT_V-78ZmChHhqksMEu59WhkA_hofadF8saneziAhCDRA","proofPurpose":"capabilityDelegation","type":"Ed25519Signature2018","verificationMethod":"did:key:z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn#z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn"}]}`)) // nolint: lll
			require.NoError(t, err)
		}

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case fn := <-edvHandlers:
				fn(w, r)
			default:
				t.Error("no handler")
			}
		}))

		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient(remoteKMS.URL, edv.URL, lKMS, store)
		require.NoError(t, err)

		vID, dURL, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "auth":{"edv":{},"kms":{"uri":"/"}}}`),
		}

		docMeta, err := client.SaveDoc(vID, docID, data["info_"+vID].Value)
		require.NoError(t, err)
		require.NotEmpty(t, docMeta.ID)
		require.NotEmpty(t, docMeta.URI)
	})

	t.Run("error if doc contents are not JSON", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string]mockstorage.DBEntry{
					"info_v_id": {Value: []byte(`{"auth":{"edv":{},"kms":{"uri":"/"}}}`)},
				},
			},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, []byte("}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode content")
	})
}

func TestClient_CreateAuthorization(t *testing.T) {
	t.Run("No authorization", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{},
		})
		require.NoError(t, err)

		_, err = client.CreateAuthorization("", "", &AuthorizationsScope{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vault info: get: data not found")
	})

	t.Run("KMS no key", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}
		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)

		client, err := NewClient("", "", lKMS, store)
		require.NoError(t, err)

		data["info_vid"] = mockstorage.DBEntry{
			Value: []byte(`{"auth":{"edv":{"authToken":""},"kms":{"authToken":""}}}`),
		}

		_, err = client.CreateAuthorization("vid", "", &AuthorizationsScope{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "kms get: getKeySet: failed")
	})

	t.Run("KMS uncompress (error)", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}
		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)

		client, err := NewClient("", "", lKMS, store)
		require.NoError(t, err)

		vID, dURL, kid := createVaultID(t, lKMS)
		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "kid":"` + kid + `","auth":{"edv":{"authToken":""},"kms":{"authToken":""}}}`), // nolint: lll
		}

		_, err = client.CreateAuthorization(vID, "", &AuthorizationsScope{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "kms uncompressZCAP: failed to init gzip reader: EOF")
	})

	t.Run("EDV uncompress (error)", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}
		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)

		client, err := NewClient("", "", lKMS, store)
		require.NoError(t, err)

		vID, dURL, kid := createVaultID(t, lKMS)
		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "kid":"` + kid + `","auth":{"edv":{"authToken":""},"kms":{"authToken":"H4sIAAAAAAAA_5SSTW-rOBSG_8u5y4EWTEzAq0lDm9CbkC86SbmqKmNs4obGyBhSUvW_j3JbzYxm1_XRq_O8H-_wJ1NHw98MENgbUzfk-vrkyeJK6fK64azV0vTXHQILZAEEWn0kbSsLwvzQ911U2MJDwh4MWWjnrnBt5oicD7AIHFRcRMdOHbgGAoUsyIH35OzPD6_bRHY5bqb7szvsRK3Lzekh54lIV_O7t7l8GGC6FssNNn7_47sCsKCmmh_NmNY0l5U0_X_Bh57Ic8dBduFxegFHNi280PZCQQd5Hg7CIQMLaFWpEy9GzEh1BPILNKcXQyctDYenT2eMXq4p1SU3QN4hjoDAKFjRaCdkbTKdJJnG_s0pmoAFaV_zLxJedKSjbWXgw4JaKyWA_HoH9g_xeE_l77ff436ygGlODb90hRzk2g6yXZQ6AcEecf2r0B8EeOBi9IeDiOOABS-nBgjw_n6fT5hcyPu77HadrjZxE7_GKBnHfvZ61zD00MSvSU93K7moGvn48ujElRteXWEeJ7vWa26mcn0ug90aLX6mtvhrHy_VgtJe5MvmnCos19l0hnDAEtv2d3py9vE4Ww690-oxUtWsb5-nCzraOH2A8_EKLDiqI7vkNdfjw8R7fKui2UyHyQOqh4dbJ2LzMw2j-Hm2510yG-KRzG-rdJuImyJ4jm1P-8FYJZkcuWrbbOee9Dc_R7lWKHNLl47gK_dlq2vVXP78G37EK17-rhYsMJ-t3RYIYzfcyPJITas5ctwALOi4lkJ-7mDOzV4V_5t6jYMunCy3y1K_pQbjjL4EyqujpAvbKO9e2LScNmxzz-6b-Y_vCuDj6ePvAAAA___BBC2CwwMAAA=="}}}`), // nolint: lll
		}
		_, err = client.CreateAuthorization(vID, vID, &AuthorizationsScope{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "edv uncompressZCAP: failed to init gzip reader: EOF")
	})

	t.Run("Success", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient("", "", lKMS, store)
		require.NoError(t, err)

		vID, dURL, kid := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "kid":"` + kid + `","auth":{"edv":{"authToken":"H4sIAAAAAAAA_5SSTW-rOBSG_8u5y4EWTEzAq0lDm9CbkC86SbmqKmNs4obGyBhSUvW_j3JbzYxm1_XRq_O8H-_wJ1NHw98MENgbUzfk-vrkyeJK6fK64azV0vTXHQILZAEEWn0kbSsLwvzQ911U2MJDwh4MWWjnrnBt5oicD7AIHFRcRMdOHbgGAoUsyIH35OzPD6_bRHY5bqb7szvsRK3Lzekh54lIV_O7t7l8GGC6FssNNn7_47sCsKCmmh_NmNY0l5U0_X_Bh57Ic8dBduFxegFHNi280PZCQQd5Hg7CIQMLaFWpEy9GzEh1BPILNKcXQyctDYenT2eMXq4p1SU3QN4hjoDAKFjRaCdkbTKdJJnG_s0pmoAFaV_zLxJedKSjbWXgw4JaKyWA_HoH9g_xeE_l77ff436ygGlODb90hRzk2g6yXZQ6AcEecf2r0B8EeOBi9IeDiOOABS-nBgjw_n6fT5hcyPu77HadrjZxE7_GKBnHfvZ61zD00MSvSU93K7moGvn48ujElRteXWEeJ7vWa26mcn0ug90aLX6mtvhrHy_VgtJe5MvmnCos19l0hnDAEtv2d3py9vE4Ww690-oxUtWsb5-nCzraOH2A8_EKLDiqI7vkNdfjw8R7fKui2UyHyQOqh4dbJ2LzMw2j-Hm2510yG-KRzG-rdJuImyJ4jm1P-8FYJZkcuWrbbOee9Dc_R7lWKHNLl47gK_dlq2vVXP78G37EK17-rhYsMJ-t3RYIYzfcyPJITas5ctwALOi4lkJ-7mDOzV4V_5t6jYMunCy3y1K_pQbjjL4EyqujpAvbKO9e2LScNmxzz-6b-Y_vCuDj6ePvAAAA___BBC2CwwMAAA=="},"kms":{"authToken":"H4sIAAAAAAAA_6RTS3PiOBj8L98c18SP2EB02oADhmBexkPC1BxkWbaFH_JIMuCk8t-3HMIc9jY1J7VK3dVSt753-JfwStGLAgSZUrVEun6-Z_EdF6kuKWkEU61-skADFn9xkK4XnOAi41KhYX_Y1_NS6jltpeKCSp0YRyuqHMabOCp-WQXPzLTTVyeeUwEIYhajnLbore_n5X7JTpEjvezNHJySWqTBOYzoMtlt_MnFZ6Ht4G2yDhzVb7_9qQA0wEXBzzR-JIrxCtAPIIJiRZ9pd0gvNRfqiiVLK9DgRAVLuv1Z4Bo0aKovQHhZN4r6j-PfrCumFRFtrUCDmN5QU8dY0Sf3-xjXOGIFU592WN6WVU07N0lx8Ql_XvMhuLvmDouUKkDvMHP_LvNdW1NA0IgK5aVENz58aFALzhNAP96_EunatQzL7BlWz7R2xhA598js3z3Y9mBg25b1j2EhwwANjmcJCGg7z6IpYSs2nxyetrtNMJOzcmYtx7P-oZxIYoVyVi5b_LJhq0Ky1-OrMSvMh7u7-7bc7UfHqTf2pjuflA8Ofr2EbzQ4L5wiOdkqtFthH9hiHDYsOZ1nrb-I3eeel2wHi2gxx6Itm01vaPV77ps52Z9Gw_V4AxpUvCLdc19W46jxh-SpyAO1fQ5ar12sKm-0dh97CWkm4Xo3GA2NMFv5wSR3cUKku_dl4k0qtrcP5uTyPVu-FL8WwZT0RvTRPKy3VWfwmdm6ETWXnQ_5Xa5LC5p-dgcaqGvoT7HlOOZDwNIKq0ZQyzCHt6_DrkX7VGU8_t9EpMfsudkfS1r1s-ZyGWfePA_WYYnvPfe8SQ6jUZZGWz4_TBPr258K4OPnx38BAAD__xy0S3b1AwAA"}}}`), // nolint: lll
		}

		created, err := client.CreateAuthorization(vID, vID, &AuthorizationsScope{
			Actions: []string{"read"},
			Caveats: []Caveat{{Type: zcapld.CaveatTypeExpiry, Duration: 100}},
		})
		require.NoError(t, err)
		require.NotEmpty(t, created.Tokens.EDV)
		require.NotEmpty(t, created.Tokens.KMS)
	})
}

func TestClient_GetDocMetadata(t *testing.T) {
	t.Run("No authorization", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{},
		})
		require.NoError(t, err)

		_, err = client.GetDocMetadata("vID", "docID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vault info: get: data not found")
	})

	t.Run("No meta doc info", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient("", "", lKMS, store)
		require.NoError(t, err)

		vID, _, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"auth":{"edv":{},"kms":{}}}`),
		}

		_, err = client.GetDocMetadata(vID, "docID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get meta doc info: store get: data not found")
	})

	t.Run("Bad meta info", func(t *testing.T) {
		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient("", "", lKMS, store)
		require.NoError(t, err)

		vID, _, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"auth":{"edv":{},"kms":{}}}`),
		}
		data["meta_doc_info_"+vID+"_docID"] = mockstorage.DBEntry{
			Value: []byte(`{`),
		}

		_, err = client.GetDocMetadata(vID, "docID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get meta doc info: store get: unexpected end of JSON")
	})

	t.Run("Success", func(t *testing.T) {
		edvHandlers := make(chan func(w http.ResponseWriter, r *http.Request), 1)
		edvHandlers <- func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "localhost:7777/encrypted-data-vaults/DWPPbEVn1afJY4We3kpQmq")
			w.WriteHeader(http.StatusOK)

			_, err := w.Write([]byte(`{"@context":"https://w3id.org/security/v2","id":"urn:uuid:293817e5-3a47-4685-9bd3-51eba3d5e928","invoker":"did:key:z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr#z6MkqknydjnZe6ZqXNGEvjYTPxwmUzAkzS17LAJTuYsMQsyr","parentCapability":"urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14","allowedAction":["read","write"],"invocationTarget":{"ID":"DWPPbEVn1afJY4We3kpQmq","Type":"urn:edv:vault"},"proof":[{"capabilityChain":["urn:uuid:3e7f55ea-2e2c-41bd-a167-3cb71db9ca14"],"created":"2021-01-31T13:41:13.863452194+02:00","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..NfznOmAi16H7fXJ1lI3-JzzHlOMopAhdGnBaF_FYK_F5BHbJMpH0u1aZ_JMgrG2XHUFMLNCBxG91DA-tJn2gDQ","nonce":"ZjtzLnBIpSNLteskV4bgTI8LOwrqrETpDI31qPglCNT_V-78ZmChHhqksMEu59WhkA_hofadF8saneziAhCDRA","proofPurpose":"capabilityDelegation","type":"Ed25519Signature2018","verificationMethod":"did:key:z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn#z6Mkpi5ZtFzsZv5UQhLzejwaNM5YX38cHBuMopUkayU13zyn"}]}`)) // nolint: lll
			require.NoError(t, err)
		}

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case fn := <-edvHandlers:
				fn(w, r)
			default:
				t.Error("no handler")
			}
		}))

		const docID = "docID"

		data := map[string]mockstorage.DBEntry{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient("", edv.URL, lKMS, store)
		require.NoError(t, err)

		vID, dURL, _ := createVaultID(t, lKMS)

		data["info_"+vID] = mockstorage.DBEntry{
			Value: []byte(`{"did_url":"` + dURL + `", "auth":{"edv":{},"kms":{}}}`),
		}
		data["meta_doc_info_"+vID+"_"+docID] = mockstorage.DBEntry{
			Value: []byte(`{"edv_id":"eURL", "kid_url":"kURL"}`),
		}

		docMeta, err := client.GetDocMetadata(vID, docID)
		require.NoError(t, err)
		require.NotEmpty(t, docMeta.ID)
		require.NotEmpty(t, docMeta.URI)
		require.NotEmpty(t, docMeta.EncKeyURI)
	})
}

const keystorePrimaryKeyURI = "local-lock://keystorekms"

func newLocalKms(t *testing.T, db storage.Provider) KeyManager {
	t.Helper()

	keyManager, err := localkms.New(keystorePrimaryKeyURI, &kmsProvider{
		storageProvider: db,
		secretLock:      &noop.NoLock{},
	})
	require.NoError(t, err)

	return keyManager
}

type kmsProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

func createVaultID(t *testing.T, k KeyManager) (string, string, string) {
	t.Helper()

	cryptoService, err := tinkcrypto.New()
	require.NoError(t, err)

	sig, err := signature.NewCryptoSigner(cryptoService, k, kms.ED25519)
	require.NoError(t, err)

	cryptoSigner, ok := sig.(interface{ KID() string })
	require.True(t, ok)

	didKey, didURL := fingerprint.CreateDIDKey(sig.PublicKeyBytes())

	return didKey, didURL, cryptoSigner.KID()
}
