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

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mocks "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edv/pkg/restapi/messages"

	. "github.com/trustbloc/edge-service/pkg/client/vault"
)

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

func TestCreateVault(t *testing.T) {
	t.Run("Crypto signer error", func(t *testing.T) {
		mKMS := &mocks.KeyManager{CreateKeyErr: errors.New("test")}

		client, err := NewClient("", "", mKMS, &mockstorage.MockStoreProvider{})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create DID key: new crypto signer: test")
	})

	t.Run("Error parse zcap", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)

			_, err := w.Write([]byte(`[]`))
			require.NoError(t, err)
		}))

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{}, &mockstorage.MockStoreProvider{})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse capability: failed to unmarshal zcap")
	})

	t.Run("KMS bad URL", func(t *testing.T) {
		client, err := NewClient("http://user^foo.com", "", &mocks.KeyManager{}, &mockstorage.MockStoreProvider{})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key store: build request for Create keystore error")
	})

	t.Run("KMS create key store error", func(t *testing.T) {
		client, err := NewClient("", "",
			&mocks.KeyManager{},
			&mockstorage.MockStoreProvider{},
			WithHTTPClient(&http.Client{}),
		)
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key store: posting Create keystore failed")
	})

	t.Run("EDV error", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{}, &mockstorage.MockStoreProvider{})
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

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{}, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{ErrPut: errors.New("test")},
		})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.EqualError(t, err, "save authorization: test")
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

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{}, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: map[string][]byte{}},
		})
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

func TestSaveDoc(t *testing.T) {
	const (
		docID   = "id"
		vaultID = "v_id"
	)

	t.Run("Unmarshal authorization error", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: map[string][]byte{"auth_v_id": []byte(`{`)}},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get authorization: unmarshal")
	})
	t.Run("No authorization", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get authorization: get: data not found")
	})

	t.Run("Encrypt key (create error)", func(t *testing.T) {
		client, err := NewClient("", "", nil, &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: map[string][]byte{"auth_v_id": []byte(`{"edv":{},"kms":{}}`)}},
		})
		require.NoError(t, err)

		_, err = client.SaveDoc(vaultID, docID, nil)
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
			payload := []byte(`{"wrappedKey": {
		 "kid": "R0tzelREUWNXckZsTVMtQk83LWFzZk5nYUZmTVo5NnQ2ZWVUaklfX1kxYw==",
		 "encryptedCEK": "5es-1SkzIwvKnM1suaYLrNnXzzUTMG28Ow5cDKCsK_yUBiCqlvtDmw==",
		 "epk": {
		  "x": "f9ccLKPnZcFwW1BroF56M1XTUG5GSYrXLAPLsi-OFsI=",
		  "y": "aqdkBFWEUZ0RWa9p4W66gPd37oe2s26gypmHZ_P0eUU=",
		  "curve": "UC0yNTY=",
		  "type": "RUM="
		 },
		 "alg": "RUNESC1FUytBMjU2S1c="
		}}`)

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

		data := map[string][]byte{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient(remoteKMS.URL, edv.URL, lKMS, store)
		require.NoError(t, err)

		vID := createVaultID(t, lKMS)

		data["auth_"+vID] = []byte(`{"edv":{},"kms":{}}`)

		docMeta, err := client.SaveDoc(vID, docID, nil)
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
			payload := []byte(`{"wrappedKey": {
		 "kid": "R0tzelREUWNXckZsTVMtQk83LWFzZk5nYUZmTVo5NnQ2ZWVUaklfX1kxYw==",
		 "encryptedCEK": "5es-1SkzIwvKnM1suaYLrNnXzzUTMG28Ow5cDKCsK_yUBiCqlvtDmw==",
		 "epk": {
		  "x": "f9ccLKPnZcFwW1BroF56M1XTUG5GSYrXLAPLsi-OFsI=",
		  "y": "aqdkBFWEUZ0RWa9p4W66gPd37oe2s26gypmHZ_P0eUU=",
		  "curve": "UC0yNTY=",
		  "type": "RUM="
		 },
		 "alg": "RUNESC1FUytBMjU2S1c="
		}}`)

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

		data := map[string][]byte{}

		store := &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{Store: data},
		}

		lKMS := newLocalKms(t, store)
		client, err := NewClient(remoteKMS.URL, edv.URL, lKMS, store)
		require.NoError(t, err)

		vID := createVaultID(t, lKMS)

		data["auth_"+vID] = []byte(`{"edv":{},"kms":{}}`)

		docMeta, err := client.SaveDoc(vID, docID, nil)
		require.NoError(t, err)
		require.NotEmpty(t, docMeta.ID)
		require.NotEmpty(t, docMeta.URI)
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

func createVaultID(t *testing.T, k KeyManager) string {
	t.Helper()

	cryptoService, err := tinkcrypto.New()
	require.NoError(t, err)

	sig, err := signature.NewCryptoSigner(cryptoService, k, kms.ED25519)
	require.NoError(t, err)

	_, didKey := fingerprint.CreateDIDKey(sig.PublicKeyBytes())

	return didKey
}
