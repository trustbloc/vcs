/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	cryptomock "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite/ecdsa2019"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	utiltime "github.com/hyperledger/aries-framework-go/component/models/util/time"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	vdrmock "github.com/hyperledger/aries-framework-go/component/vdr/mock"
	ariescrypto "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/internal/testutil"
	"github.com/trustbloc/vcs/pkg/kms/signer"
)

const (
	didID = "did:trustbloc:abc"
)

func TestCrypto_SignCredentialLDP(t *testing.T) { //nolint:gocognit
	t.Parallel()

	t.Run("test success", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVC, err := c.signCredentialLDP(
			getTestLDPSigner(), &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test successful sign credential using opts", func(t *testing.T) {
		prepareTestCreated := func(y, m, d int) *time.Time {
			c := time.Now().AddDate(y, m, d)

			return &c
		}

		tests := []struct {
			name              string
			signingOpts       []SigningOpts
			responsePurpose   string
			responseVerMethod string
			responseDomain    string
			responseChallenge string
			responseTime      *time.Time
			vcSigner          *vc.Signer
			err               string
		}{
			{
				name:              "signing with domain option",
				signingOpts:       []SigningOpts{WithDomain("example.com")},
				responsePurpose:   "authentication",
				responseVerMethod: "did:trustbloc:abc#key1",
				responseDomain:    "example.com",
			},
			{
				name:              "signing with domain option",
				signingOpts:       []SigningOpts{WithChallenge("challenge")},
				responsePurpose:   "authentication",
				responseVerMethod: "did:trustbloc:abc#key1",
				responseChallenge: "challenge",
			},
			{
				name: "signing with verification method, purpose options & representation(proofValue)",
				signingOpts: []SigningOpts{
					WithPurpose(AssertionMethod),
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSigningRepresentation("proofValue"),
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "signing with verification method, purpose, created, type & representation(jws) options",
				signingOpts: []SigningOpts{
					WithPurpose(AssertionMethod),
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSigningRepresentation("jws"),
					WithCreated(prepareTestCreated(-1, -1, 0)),
				},
				responsePurpose:   AssertionMethod,
				responseVerMethod: "did:trustbloc:abc#key1",
				responseTime:      prepareTestCreated(-1, -1, 0),
			},
			{
				name:              "signing with verification method & purpose options",
				signingOpts:       []SigningOpts{},
				responsePurpose:   "authentication",
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "failed with invalid signing representation",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSigningRepresentation("xyz"),
				},
				err: "invalid proof format : xyz",
			},
			{
				name: "test with JsonWebSignature2020",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSignatureType("JsonWebSignature2020"),
				},
				responsePurpose:   "authentication",
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "test with EcdsaSecp256k1Signature2019",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSignatureType("EcdsaSecp256k1Signature2019"),
				},
				responsePurpose:   "authentication",
				responseVerMethod: "did:trustbloc:abc#key1",
			},
			{
				name: "failed with unsupported signature type",
				signingOpts: []SigningOpts{
					WithVerificationMethod("did:trustbloc:abc#key1"),
					WithSignatureType("123"),
				},
				err: "signature type unsupported 123",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				c := New(
					&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
					testutil.DocumentLoader(t),
				)

				vcSigner := getTestLDPSigner()
				if tc.vcSigner != nil {
					vcSigner = tc.vcSigner
				}

				signedVC, err := c.signCredentialLDP(
					vcSigner, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
					tc.signingOpts...)

				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				require.NoError(t, err)
				require.Equal(t, 1, len(signedVC.Proofs))
				require.Equal(t, tc.responsePurpose, signedVC.Proofs[0]["proofPurpose"])
				require.Equal(t, tc.responseVerMethod, signedVC.Proofs[0]["verificationMethod"])
				require.NotEmpty(t, signedVC.Proofs[0]["created"])

				if signedVC.Proofs[0]["challenge"] != nil {
					require.Equal(t, tc.responseChallenge, signedVC.Proofs[0]["challenge"].(string))
				}

				if signedVC.Proofs[0]["domain"] != nil {
					require.Equal(t, tc.responseDomain, signedVC.Proofs[0]["domain"].(string))
				}

				created, err := time.Parse(time.RFC3339, signedVC.Proofs[0]["created"].(string))
				require.NoError(t, err)

				responseTime := time.Now()

				if tc.responseTime != nil {
					responseTime = *tc.responseTime
				}

				require.Equal(t, responseTime.Year(), created.Year())
				require.Equal(t, responseTime.Month(), created.Month())
			})
		}
	})

	t.Run("test error from creator", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)
		p := getTestLDPSigner()
		p.Creator = "wrongValue"
		signedVC, err := c.signCredentialLDP(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "verificationMethod value wrongValue should be in did#keyID format")
		require.Nil(t, signedVC)
	})

	t.Run("test error from sign credential", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)
		signedVC, err := c.signCredentialLDP(
			&vc.Signer{
				KeyType:       kms.ED25519Type,
				DID:           "did:trustbloc:abc",
				SignatureType: "Ed25519Signature2018",
				Creator:       "did:trustbloc:abc#key1",
				KMS: &mockVCSKeyManager{
					kms:    &mockkms.KeyManager{},
					crypto: &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}},
			},
			&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
		require.Nil(t, signedVC)
	})

	t.Run("sign vc - invalid proof purpose", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")}, testutil.DocumentLoader(t))

		p := getTestLDPSigner()

		signedVC, err := c.signCredentialLDP(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
			WithPurpose("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "proof purpose invalid not supported")
		require.Nil(t, signedVC)
	})

	t.Run("sign vc - capability invocation proof purpose", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")}, testutil.DocumentLoader(t))

		p := getTestLDPSigner()

		signedVC, err := c.signCredentialLDP(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
			WithPurpose(CapabilityInvocation))
		require.NoError(t, err)
		require.NotNil(t, signedVC)
	})

	t.Run("sign vc - capability delegation proof purpose", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")}, testutil.DocumentLoader(t))

		p := getTestLDPSigner()

		signedVC, err := c.signCredentialLDP(
			p, &verifiable.Credential{ID: "http://example.edu/credentials/1872"},
			WithPurpose(CapabilityInvocation))
		require.NoError(t, err)
		require.NotNil(t, signedVC)
	})
}

func TestCrypto_SignCredentialJWT(t *testing.T) {
	unsignedVc := verifiable.Credential{
		ID:      "http://example.edu/credentials/1872",
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Subject: verifiable.Subject{
			ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
			CustomFields: map[string]interface{}{
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"name":   "Jayden Doe",
				"degree": map[string]interface{}{
					"type":   "BachelorDegree",
					"degree": "MIT",
				},
			},
		},
		Issued: &utiltime.TimeWrapper{
			Time: time.Now(),
		},
		Issuer: verifiable.Issuer{
			ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
		},
		CustomFields: map[string]interface{}{
			"first_name": "First name",
			"last_name":  "Last name",
			"info":       "Info",
		},
	}

	customKMS := createKMS(t)

	customCrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	keyID, _, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	didDoc := createDIDDoc(didID, func(vm *did.VerificationMethod) {
		vm.ID = didID + "#" + keyID
	})

	type fields struct {
		getVDR func() vdrapi.Registry
	}
	type args struct {
		signerData *vc.Signer
		getVC      func() *verifiable.Credential
		opts       []SigningOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "OK empty options",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: nil,
			},
			wantErr: false,
		},
		{
			name: "OK with options",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{
					WithSignatureType("JsonWebSignature2020"),
					WithVerificationMethod(didID + "#" + keyID),
					WithPurpose(AssertionMethod),
				},
			},
			wantErr: false,
		},
		{
			name: "OK with options SD-JWT",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getSDJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{
					WithSignatureType("JsonWebSignature2020"),
					WithVerificationMethod(didID + "#" + keyID),
					WithPurpose(AssertionMethod),
				},
			},
			wantErr: false,
		},
		{
			name: "SD JWT signing error",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getSDJWTSigner(
					&cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{},
			},
			wantErr: true,
		},
		{
			name: "Error GetDIDDocFromVerificationMethod",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveErr: errors.New("some error")}
				},
			},
			args: args{
				signerData: getJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{},
			},
			wantErr: true,
		},
		{
			name: "Error proof purpose not supported",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{
					WithPurpose("keyAgreement"),
				},
			},
			wantErr: true,
		},
		{
			name: "Error unable to find matching key ID from DID",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					doc := createDIDDoc(didID)
					doc.AssertionMethod[0].VerificationMethod.ID = ""
					return &vdrmock.VDRegistry{ResolveValue: doc}
				},
			},
			args: args{
				signerData: getJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{},
			},
			wantErr: true,
		},
		{
			name: "Error empty VC subject",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getJWTSigner(customCrypto, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					cred := unsignedVc
					cred.Subject = nil
					return &cred
				},
				opts: []SigningOpts{},
			},
			wantErr: true,
		},
		{
			name: "Error kms:unsupported key type",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: &vc.Signer{
					DID:           didID,
					SignatureType: "Ed25519Signature2018",
					Creator:       didID + "#" + keyID,
					KMSKeyID:      keyID,
					KMS: &mockVCSKeyManager{
						crypto: customCrypto,
						kms:    customKMS,
					},
					Format:  vcsverifiable.Jwt,
					KeyType: "unsupported",
				},
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{},
			},
			wantErr: true,
		},
		{
			name: "JWS signing error",
			fields: fields{
				getVDR: func() vdrapi.Registry {
					return &vdrmock.VDRegistry{ResolveValue: didDoc}
				},
			},
			args: args{
				signerData: getJWTSigner(
					&cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")}, customKMS, keyID),
				getVC: func() *verifiable.Credential {
					return &unsignedVc
				},
				opts: []SigningOpts{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Crypto{
				vdr:            tt.fields.getVDR(),
				documentLoader: testutil.DocumentLoader(t),
			}
			got, err := c.signCredentialJWT(tt.args.signerData, tt.args.getVC(), tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignCredentialJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got.JWT == "" {
				t.Errorf("JWT field empty")
			}
			if len(got.Proofs) > 0 {
				t.Errorf("Proof field is not empty")
			}
		})
	}
}

func TestCrypto_SignCredentialBBS(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVC, err := c.signCredentialLDP(
			&vc.Signer{
				DID:           "did:trustbloc:abc",
				SignatureType: "BbsBlsSignature2020",
				Creator:       "did:trustbloc:abc#key1",
				KMSKeyID:      "key1",
				KMS: &mockVCSKeyManager{
					crypto: &cryptomock.Crypto{},
					kms:    &mockkms.KeyManager{},
				},
			}, &verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})
}

func TestSignPresentation(t *testing.T) {
	t.Run("sign presentation - success", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVP, err := c.SignPresentation(getTestLDPSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
		)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVP.Proofs))
	})

	t.Run("sign presentation - signature type opts", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVP, err := c.SignPresentation(getTestLDPSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
			WithSignatureType(vcsverifiable.Ed25519Signature2020),
		)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVP.Proofs))
	})

	t.Run("sign presentation - fail", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		signedVP, err := c.SignPresentation(getTestLDPSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
			WithSignatureType("invalid"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type unsupported invalid")
		require.Nil(t, signedVP)
	})

	t.Run("sign presentation - unresolved did", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: nil},
			nil,
		)

		signedVP, err := c.SignPresentation(getTestLDPSigner(),
			&verifiable.Presentation{ID: "http://example.edu/presentation/1872"},
			WithSignatureType(vcsverifiable.Ed25519Signature2018),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DID does not exist")
		require.Nil(t, signedVP)
	})
}

func TestSignCredential(t *testing.T) {
	t.Run("sign credential LDP - success", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		unsignedVC := &verifiable.Credential{
			ID: "http://example.edu/credentials/1872",
		}

		signedVC, err := c.SignCredential(getTestLDPSigner(), unsignedVC)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
		require.Empty(t, signedVC.JWT)
	})
	t.Run("sign credential LDP Data Integrity - success", func(t *testing.T) {
		customKMS := createKMS(t)

		_, keyBytes, err := customKMS.CreateAndExportPubKeyBytes(kms.ECDSAP256IEEEP1363)
		require.NoError(t, err)

		key, err := jwkkid.BuildJWK(keyBytes, kms.ECDSAP256IEEEP1363)
		require.NoError(t, err)

		const signingDID = "did:foo:bar"

		const vmID = "#key1"

		verificationMethod, err := did.NewVerificationMethodFromJWK(vmID, "JsonWebKey2020", signingDID, key)
		require.NoError(t, err)

		c := New(
			&vdrmock.VDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return makeMockDIDResolution(signingDID, verificationMethod, did.Authentication), nil
				}},
			testutil.DocumentLoader(t),
		)

		unsignedVc := verifiable.Credential{
			ID:      "http://example.edu/credentials/1872",
			Context: []string{verifiable.ContextURI},
			Types:   []string{verifiable.VCType},
			Subject: verifiable.Subject{
				ID: "did:example:ebfeb1f712ebc6f1c276e12ec21",
				CustomFields: map[string]interface{}{
					"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
					"name":   "Jayden Doe",
					"degree": map[string]interface{}{
						"type":   "BachelorDegree",
						"degree": "MIT",
					},
				},
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Now(),
			},
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			CustomFields: map[string]interface{}{
				"first_name": "First name",
				"last_name":  "Last name",
				"info":       "Info",
			},
		}

		signedVC, err := c.SignCredential(getTestLDPDataIntegritySigner(), &unsignedVc)
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
		require.Empty(t, signedVC.JWT)
	})
	t.Run("sign credential LDP - error", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: nil},
			testutil.DocumentLoader(t),
		)

		unsignedVC := &verifiable.Credential{
			ID: "http://example.edu/credentials/1872",
		}

		signedVC, err := c.SignCredential(getTestLDPSigner(), unsignedVC)
		require.Error(t, err)
		require.Nil(t, signedVC)
	})
	t.Run("sign credential - error undefined format", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: nil},
			testutil.DocumentLoader(t),
		)

		unsignedVC := &verifiable.Credential{
			ID: "http://example.edu/credentials/1872",
		}

		signedVC, err := c.SignCredential(&vc.Signer{
			DID:           "did:trustbloc:abc",
			SignatureType: "Ed25519Signature2018",
			Creator:       "did:trustbloc:abc#key1",
			KMSKeyID:      "key1",
			KMS: &mockVCSKeyManager{
				crypto: &cryptomock.Crypto{},
				kms:    &mockkms.KeyManager{},
			},
		}, unsignedVC)
		require.Error(t, err)
		require.ErrorContains(t, err, "unknown signature format")
		require.Nil(t, signedVC)
	})
	t.Run("sign credential JWT - success", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		unsignedVC := &verifiable.Credential{
			ID:      "http://example.edu/credentials/1872",
			Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			Issued: &utiltime.TimeWrapper{
				Time: time.Now(),
			},
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
		}

		signedVC, err := c.SignCredential(&vc.Signer{
			DID:           "did:trustbloc:abc",
			SignatureType: "Ed25519Signature2018",
			Creator:       "did:trustbloc:abc#key1",
			KMSKeyID:      "key1",
			KeyType:       kms.ED25519Type,
			KMS: &mockVCSKeyManager{
				crypto: &cryptomock.Crypto{},
				kms:    &mockkms.KeyManager{},
			},
			Format: vcsverifiable.Jwt,
		}, unsignedVC)
		require.NoError(t, err)
		require.NotNil(t, signedVC)
		require.NotEmpty(t, signedVC.JWT)
		require.False(t, strings.Contains(signedVC.JWT, common.CombinedFormatSeparator))
	})
	t.Run("sign credential JWT - error", func(t *testing.T) {
		c := New(
			&vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
			testutil.DocumentLoader(t),
		)

		unsignedVC := &verifiable.Credential{
			ID:      "http://example.edu/credentials/1872",
			Subject: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			Issuer: verifiable.Issuer{
				ID: "did:example:76e12ec712ebc6f1c221ebfeb1f",
			},
			Issued: &utiltime.TimeWrapper{
				Time: time.Now(),
			},
		}

		signedVC, err := c.SignCredential(&vc.Signer{
			DID:           "did:trustbloc:abc",
			SignatureType: "Ed25519Signature2018",
			Creator:       "did:trustbloc:abc#key1",
			KMSKeyID:      "key1",
			KMS: &mockVCSKeyManager{
				crypto: &cryptomock.Crypto{},
				kms:    &mockkms.KeyManager{},
			},
			Format: vcsverifiable.Jwt,
		}, unsignedVC)
		require.Error(t, err)
		require.Nil(t, signedVC)
	})
}

func getTestLDPSigner() *vc.Signer {
	return &vc.Signer{
		DID:           "did:trustbloc:abc",
		SignatureType: "Ed25519Signature2018",
		Creator:       "did:trustbloc:abc#key1",
		KMSKeyID:      "key1",
		KeyType:       kms.ED25519,
		KMS: &mockVCSKeyManager{
			crypto: &cryptomock.Crypto{},
			kms:    &mockkms.KeyManager{},
		},
		Format: vcsverifiable.Ldp,
		DataIntegrityProof: vc.DataIntegrityProofConfig{
			Enable: false,
		},
	}
}

func getTestLDPDataIntegritySigner() *vc.Signer {
	s := getTestLDPSigner()
	s.DataIntegrityProof = vc.DataIntegrityProofConfig{
		Enable:    true,
		SuiteType: ecdsa2019.SuiteType,
	}

	return s
}

func getJWTSigner(
	customCrypto ariescrypto.Crypto,
	customKMS kms.KeyManager,
	kid string) *vc.Signer {
	return &vc.Signer{
		DID:           didID,
		SignatureType: "Ed25519Signature2018",
		Creator:       didID + "#" + kid,
		KMSKeyID:      kid,
		KMS: &mockVCSKeyManager{
			crypto: customCrypto,
			kms:    customKMS,
		},
		Format:  vcsverifiable.Jwt,
		KeyType: kms.ED25519Type,
	}
}

func getSDJWTSigner(
	customCrypto ariescrypto.Crypto,
	customKMS kms.KeyManager,
	kid string) *vc.Signer {
	s := getJWTSigner(customCrypto, customKMS, kid)
	s.SDJWT = vc.SDJWT{Enable: true, HashAlg: crypto.SHA384}

	return s
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p, err := mockkms.NewProviderForKMS(ariesmockstorage.NewMockStoreProvider(), &noop.NoLock{})
	require.NoError(t, err)

	k, err := localkms.New("local-lock://custom/primary/key/", p)
	require.NoError(t, err)

	return k
}

type mockVCSKeyManager struct {
	err    error
	crypto ariescrypto.Crypto
	kms    kms.KeyManager
}

func (m *mockVCSKeyManager) NewVCSigner(creator string,
	signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	if m.err != nil {
		return nil, m.err
	}

	return signer.NewKMSSigner(m.kms, m.crypto, creator, signatureType, nil)
}

type opt func(vm *did.VerificationMethod)

// nolint: unparam
func createDIDDoc(didID string, opts ...opt) *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	creator := didID + "#key1"

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}
	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	for _, f := range opts {
		f(&signingKey)
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:              []string{didContext},
		ID:                   didID,
		VerificationMethod:   []did.VerificationMethod{signingKey},
		Service:              []did.Service{service},
		Created:              &createdTime,
		AssertionMethod:      []did.Verification{{VerificationMethod: signingKey}},
		Authentication:       []did.Verification{{VerificationMethod: signingKey, Relationship: did.Authentication}},
		CapabilityInvocation: []did.Verification{{VerificationMethod: signingKey}},
		CapabilityDelegation: []did.Verification{{VerificationMethod: signingKey}},
	}
}

func TestCrypto_NewJWTSigned(t *testing.T) {
	testClaims := map[string]interface{}{
		"key": "value",
	}

	type fields struct {
		vdr            vdrapi.Registry
		documentLoader ld.DocumentLoader
	}
	type args struct {
		getClaims     func() interface{}
		getSignerData func() *vc.Signer
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Success",
			fields: fields{
				vdr:            &vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
				documentLoader: testutil.DocumentLoader(t),
			},
			args: args{
				getClaims: func() interface{} {
					return testClaims
				},
				getSignerData: getTestLDPSigner,
			},
			want:    "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp0cnVzdGJsb2M6YWJjI2tleTEifQ.eyJrZXkiOiJ2YWx1ZSJ9.",
			wantErr: false,
		},
		{
			name: "Error KeyTypeToJWSAlgo",
			fields: fields{
				vdr:            &vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
				documentLoader: testutil.DocumentLoader(t),
			},
			args: args{
				getClaims: func() interface{} {
					return testClaims
				},
				getSignerData: func() *vc.Signer {
					s := getTestLDPSigner()
					s.KeyType = ""

					return s
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Error getSigner",
			fields: fields{
				vdr:            &vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
				documentLoader: testutil.DocumentLoader(t),
			},
			args: args{
				getClaims: func() interface{} {
					return testClaims
				},
				getSignerData: func() *vc.Signer {
					s := getTestLDPSigner()
					s.KMS = &mockVCSKeyManager{
						err: errors.New("some error"),
					}

					return s
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Error NewSigned",
			fields: fields{
				vdr:            &vdrmock.VDRegistry{ResolveValue: createDIDDoc("did:trustbloc:abc")},
				documentLoader: testutil.DocumentLoader(t),
			},
			args: args{
				getClaims: func() interface{} {
					return func() {}
				},
				getSignerData: getTestLDPSigner,
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Crypto{
				vdr:            tt.fields.vdr,
				documentLoader: tt.fields.documentLoader,
			}
			got, err := c.NewJWTSigned(tt.args.getClaims(), tt.args.getSignerData())
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJWTSigned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewJWTSigned() got = %v, want %v", got, tt.want)
			}
		})
	}
}
