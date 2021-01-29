/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"

	. "github.com/trustbloc/edge-service/pkg/client/vault"
)

func TestCreateVault(t *testing.T) {
	t.Run("Crypto signer error", func(t *testing.T) {
		kms := &mocks.KeyManager{CreateKeyErr: errors.New("test")}

		client, err := NewClient("", "", kms)
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

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse capability: failed to unmarshal zcap")
	})

	t.Run("KMS bad URL", func(t *testing.T) {
		client, err := NewClient("http://user^foo.com", "", &mocks.KeyManager{})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key store: new request: parse")
	})

	t.Run("KMS create key store error", func(t *testing.T) {
		client, err := NewClient("", "", &mocks.KeyManager{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key store: http Do:")
	})

	t.Run("EDV error", func(t *testing.T) {
		remoteKMS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		edv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{})
		require.NoError(t, err)

		_, err = client.CreateVault()
		require.Error(t, err)
		require.Contains(t, err.Error(), "the EDV server returned status code 400")
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

		client, err := NewClient(remoteKMS.URL, edv.URL, &mocks.KeyManager{})
		require.NoError(t, err)

		result, err := client.CreateVault()
		require.NoError(t, err)
		require.NotEmpty(t, result.ID)
		require.NotEmpty(t, result.EDV.URI)
		require.NotEmpty(t, result.EDV.ZCAP)
		require.NotEmpty(t, result.KMS.URI)
		require.NotEmpty(t, result.KMS.ZCAP)
	})
}
