/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentation

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"
	cwt2 "github.com/trustbloc/vc-go/verifiable/cwt"
	"github.com/veraison/go-cose"

	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/observability/metrics/noop"
)

const (
	tokenLifetimeSeconds = 600
)

type CreateVpTokenRequest struct {
	ClientID       string
	Nonce          string
	VPFormats      *presexch.Format
	Wallet         *wallet.Wallet
	CryptoSuite    api.Suite
	VdrRegistry    vdrapi.Registry
	DocumentLoader ld.DocumentLoader
}

type VPTokenClaims struct {
	VP    *verifiable.Presentation `json:"vp"`
	Nonce string                   `json:"nonce"`
	Exp   int64                    `json:"exp"`
	Iss   string                   `json:"iss"`
	Aud   string                   `json:"aud"`
	Nbf   int64                    `json:"nbf"`
	Iat   int64                    `json:"iat"`
	Jti   string                   `json:"jti"`
}

func CreateVPToken(
	presentations []*verifiable.Presentation,
	req *CreateVpTokenRequest,
) ([]string, error) {
	credential := presentations[0].Credentials()[0]

	subjectDID, err := verifiable.SubjectID(credential.Contents().Subject)
	if err != nil {
		return nil, fmt.Errorf("get subject did: %w", err)
	}

	vpFormats := req.VPFormats

	var vpTokens []string

	for _, presentation := range presentations {
		var (
			vpToken string
			signErr error
		)

		switch {
		case vpFormats.JwtVP != nil:
			if vpToken, signErr = signPresentationJWT(
				presentation,
				subjectDID,
				req,
			); signErr != nil {
				return nil, signErr
			}
		case vpFormats.LdpVP != nil:
			if vpToken, signErr = signPresentationLDP(
				presentation,
				vcs.SignatureType(vpFormats.LdpVP.ProofType[0]),
				subjectDID,
				req,
			); signErr != nil {
				return nil, signErr
			}
		case vpFormats.CwtVP != nil:
			if vpToken, signErr = signPresentationCWT(
				presentation,
				subjectDID,
				req,
			); signErr != nil {
				return nil, signErr
			}
		default:
			return nil, fmt.Errorf("unsupported vp formats: %v", vpFormats)
		}

		vpTokens = append(vpTokens, vpToken)
	}

	return vpTokens, nil
}

func signPresentationCWT(
	vp *verifiable.Presentation,
	signerDID string,
	req *CreateVpTokenRequest,
) (string, error) {
	var (
		kmsKeyID string
		//kmsKeyType kms.KeyType
		coseAlgo cose.Algorithm
		err      error
	)

	for _, didInfo := range req.Wallet.DIDs() {
		if didInfo.ID == signerDID {
			kmsKeyID = didInfo.KeyID

			coseAlgo, err = verifiable.KeyTypeToCWSAlgo(didInfo.KeyType)
			if err != nil {
				return "", fmt.Errorf("convert key type to cose algorithm: %w", err)
			}

			break
		}
	}

	signer, err := req.CryptoSuite.FixedKeyMultiSigner(kmsKeyID)
	if err != nil {
		return "", fmt.Errorf("create signer for key %s: %w", kmsKeyID, err)
	}

	kmsSigner := kmssigner.NewKMSSigner(signer, req.Wallet.SignatureType(), nil)

	claims := VPTokenClaims{
		VP:    vp,
		Nonce: req.Nonce,
		Exp:   time.Now().Unix() + tokenLifetimeSeconds,
		Iss:   signerDID,
		Aud:   req.ClientID,
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}

	//
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal cbor claims: %w", err)
	}

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: coseAlgo,
				cose.HeaderLabelKeyID:     []byte(kmsKeyID),
			},
			Unprotected: cose.UnprotectedHeader{
				cose.HeaderLabelContentType: "application/vc+ld+json+cose",
			},
		},
		Payload: payload,
	}

	//verifiable.KeyTypeToCWSAlgo(f.wallet.SignatureType()
	signData, err := cwt2.GetProofValue(msg)
	if err != nil {
		return "", err
	}

	signed, err := kmsSigner.Sign(signData)
	if err != nil {
		return "", err
	}

	msg.Signature = signed

	final, err := cbor.Marshal(msg)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(final), nil
}

func signPresentationJWT(
	vp *verifiable.Presentation,
	signerDID string,
	req *CreateVpTokenRequest,
) (string, error) {
	docResolution, err := req.VdrRegistry.Resolve(signerDID)
	if err != nil {
		return "", fmt.Errorf("resolve signer did: %w", err)
	}

	verificationMethod := docResolution.DIDDocument.VerificationMethod[0]

	var kmsKeyID string

	for _, didInfo := range req.Wallet.DIDs() {
		if didInfo.ID == signerDID {
			kmsKeyID = didInfo.KeyID
			break
		}
	}

	signer, err := req.CryptoSuite.FixedKeyMultiSigner(kmsKeyID)
	if err != nil {
		return "", fmt.Errorf("create signer for key %s: %w", kmsKeyID, err)
	}

	kmsSigner := kmssigner.NewKMSSigner(signer, req.Wallet.SignatureType(), nil)

	claims := VPTokenClaims{
		VP:    vp,
		Nonce: req.Nonce,
		Exp:   time.Now().Unix() + tokenLifetimeSeconds,
		Iss:   signerDID,
		Aud:   req.ClientID,
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}

	signedJWT, err := jwt.NewJoseSigned(
		claims,
		map[string]interface{}{"typ": "JWT"},
		jwssigner.NewJWSSigner(
			verificationMethod.ID,
			string(req.Wallet.SignatureType()),
			kmsSigner,
		),
	)
	if err != nil {
		return "", fmt.Errorf("create signed jwt: %w", err)
	}

	jws, err := signedJWT.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serialize signed jwt: %w", err)
	}

	return jws, nil
}

func signPresentationLDP(
	vp *verifiable.Presentation,
	signatureType vcs.SignatureType,
	signerDID string,
	req *CreateVpTokenRequest,
) (string, error) {
	cryptoSigner := vccrypto.New(req.VdrRegistry, req.DocumentLoader)

	vp.Context = append(vp.Context, "https://w3id.org/security/suites/jws-2020/v1")

	docResolution, err := req.VdrRegistry.Resolve(signerDID)
	if err != nil {
		return "", fmt.Errorf("resolve signer did: %w", err)
	}

	verificationMethod := docResolution.DIDDocument.VerificationMethod[0]

	var (
		kmsKeyID   string
		kmsKeyType kms.KeyType
	)

	for _, didInfo := range req.Wallet.DIDs() {
		if didInfo.ID == signerDID {
			kmsKeyID = didInfo.KeyID
			kmsKeyType = didInfo.KeyType
			break
		}
	}

	signedVP, err := cryptoSigner.SignPresentation(
		&vc.Signer{
			Creator:                 verificationMethod.ID,
			KeyType:                 kmsKeyType,
			KMSKeyID:                kmsKeyID,
			SignatureType:           signatureType,
			SignatureRepresentation: verifiable.SignatureProofValue,
			KMS:                     vcskms.GetAriesKeyManager(req.CryptoSuite, vcskms.Local, noop.GetMetrics()),
		},
		vp,
		vccrypto.WithChallenge(req.Nonce),
		vccrypto.WithDomain(req.ClientID),
	)
	if err != nil {
		return "", fmt.Errorf("sign vp: %w", err)
	}

	var b []byte

	b, err = signedVP.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal signed vp: %w", err)
	}

	return string(b), nil
}
