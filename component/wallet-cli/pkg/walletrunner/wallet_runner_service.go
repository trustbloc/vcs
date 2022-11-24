/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"fmt"
	"log"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms/signer"
)

const (
	vdrResolveMaxRetry = 10
)

type Service struct {
	ariesServices  *AriesServices
	wallet         *wallet.Wallet
	vcProvider     vcprovider.VCProvider
	vcProviderConf *vcprovider.Config
}

func New(vcProviderType string, opts ...vcprovider.ConfigOption) (*Service, error) {
	vcProvider, err := vcprovider.GetProvider(vcProviderType, opts...)
	if err != nil {
		return nil, fmt.Errorf("GetVCProvider err: %w", err)
	}

	return &Service{
		vcProvider:     vcProvider,
		vcProviderConf: vcProvider.GetConfig(),
	}, nil
}

func (s *Service) GetConfig() *vcprovider.Config {
	return s.vcProviderConf
}

func (s *Service) RunOIDC4VPFlow(authorizationRequest string) error {
	log.Println("Start OIDC4VP flow")
	log.Println("AuthorizationRequest:", authorizationRequest)

	log.Println("Creating wallet")
	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	log.Println("Issuing credentials")
	vcData, err := s.vcProvider.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed getting VC: %w", err)
	}

	log.Println("Saving credentials to wallet")
	for _, vcBytes := range vcData {
		err = s.SaveCredentialInWallet(vcBytes)
		if err != nil {
			return fmt.Errorf("error save VC to wallet : %w", err)
		}
	}
	log.Println(len(vcData), "credentials were saved to wallet")

	vpFlowExecutor := s.NewVPFlowExecutor()

	log.Println("Fetching request object")
	rawRequestObject, err := vpFlowExecutor.FetchRequestObject(authorizationRequest)
	if err != nil {
		return err
	}

	log.Println("Resolving request object")
	err = vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
	if err != nil {
		return err
	}

	log.Println("Querying VC from wallet")
	err = vpFlowExecutor.QueryCredentialFromWallet()
	if err != nil {
		return err
	}

	log.Println("Creating authorized response")
	authorizedResponse, err := vpFlowExecutor.CreateAuthorizedResponse()
	if err != nil {
		return err
	}

	log.Println("Sending authorized response")
	err = vpFlowExecutor.SendAuthorizedResponse(authorizedResponse)
	if err != nil {
		return err
	}

	log.Println("Credentials shared with verifier")
	return nil
}

func verifyTokenSignature(rawJwt string, claims interface{}, verifier jose.SignatureVerifier) error {
	jsonWebToken, err := jwt.Parse(rawJwt, jwt.WithSignatureVerifier(verifier))
	if err != nil {
		return fmt.Errorf("parse JWT: %w", err)
	}

	err = jsonWebToken.DecodeClaims(claims)
	if err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}

	return nil
}

func createLDStore(storageProvider storage.Provider) (*ldStoreProvider, error) {
	contextStore, err := ldstore.NewContextStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	return &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}, nil
}

type kmsProvider struct {
	store             kms.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kms.Store {
	return k.store
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

type webVDR struct {
	http *http.Client
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*ariesdid.DocResolution, error) {
	docRes, err := w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
	if err != nil {
		return nil, fmt.Errorf("failed to read did web: %w", err)
	}

	return docRes, nil
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func signToken(claims interface{}, didKeyID string, crpt crypto.Crypto,
	km kms.KeyManager) (string, error) {

	signr, err := signer.NewKMSSigner(km, crpt, didKeyID, "ES384", nil)

	token, err := jwt.NewSigned(claims, nil, NewJWSSigner(didKeyID, "ES384", signr))
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}

type JWSSigner struct {
	keyID            string
	signingAlgorithm string
	signer           vc.SignerAlgorithm
}

func NewJWSSigner(keyID string, signingAlgorithm string, signer vc.SignerAlgorithm) *JWSSigner {
	return &JWSSigner{
		keyID:            keyID,
		signingAlgorithm: signingAlgorithm,
		signer:           signer,
	}
}

// Sign signs.
func (s *JWSSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

// Headers provides JWS headers. "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1)
func (s *JWSSigner) Headers() jose.Headers {
	return jose.Headers{
		jose.HeaderKeyID:     s.keyID,
		jose.HeaderAlgorithm: s.signingAlgorithm,
	}
}
