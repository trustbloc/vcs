/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletrunner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
	"github.com/samber/lo"
	"github.com/valyala/fastjson"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/presexch"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	didkey "github.com/hyperledger/aries-framework-go/component/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/httputil"
	"github.com/trustbloc/vcs/pkg/doc/vc"
	vccrypto "github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
	vcskms "github.com/trustbloc/vcs/pkg/kms"
	"github.com/trustbloc/vcs/pkg/kms/signer"
	"github.com/trustbloc/vcs/pkg/observability/metrics/noop"
)

type RPConfigOverride func(rpc *RPConfig)

func WithSupportedVPFormat(vpFormat vcs.Format) RPConfigOverride {
	return func(rpc *RPConfig) {
		rpc.supportedVPFormat = vpFormat
	}
}

type OIDC4VPHooks struct {
	CreateAuthorizedResponse []RPConfigOverride
}

func (s *Service) RunOIDC4VPFlow(ctx context.Context, authorizationRequest string, hooks *OIDC4VPHooks) error {
	log.Println("Start OIDC4VP flow")
	log.Println("AuthorizationRequest:", authorizationRequest)

	err := s.CreateWallet()
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	if s.vcProviderConf.OIDC4VPShouldFetchCredentials {
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
	} else {
		log.Println("Using existing credentials")
	}

	s.vpFlowExecutor = s.NewVPFlowExecutor(s.vcProviderConf.SkipSchemaValidation)

	log.Println("Fetching request object")
	startTime := time.Now()
	rawRequestObject, dur, err := s.vpFlowExecutor.FetchRequestObject(authorizationRequest)
	s.perfInfo.FetchRequestObject = dur
	s.perfInfo.VcsVPFlowDuration += dur
	if err != nil {
		return err
	}

	log.Println("Resolving request object")
	startTime = time.Now()
	err = s.vpFlowExecutor.VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject)
	if err != nil {
		return err
	}

	if s.vcProviderConf.LinkedDomainVerificationEnabled {
		if err := s.runLinkedDomainVerification(s.vpFlowExecutor.requestObject.ClientID); err != nil {
			return fmt.Errorf("linked domain verification failed: %w", err)
		}
	}

	s.perfInfo.VerifyAuthorizationRequest = time.Since(startTime)

	log.Println("Querying VC from wallet")
	startTime = time.Now()
	err = s.vpFlowExecutor.QueryCredentialFromWalletSingleVP()
	if err != nil {
		return err
	}
	s.perfInfo.QueryCredentialFromWallet = time.Since(startTime)
	if !s.vcProviderConf.KeepWalletOpen {
		s.wallet.Close()
	}

	var createAuthorizedResponseHooks []RPConfigOverride
	if hooks != nil {
		createAuthorizedResponseHooks = hooks.CreateAuthorizedResponse
	}

	log.Println("Creating authorized response")
	startTime = time.Now()
	authorizedResponse, err := s.vpFlowExecutor.CreateAuthorizedResponse(createAuthorizedResponseHooks...)
	if err != nil {
		return err
	}
	s.perfInfo.CreateAuthorizedResponse = time.Since(startTime)

	log.Println("Sending authorized response")
	startTime = time.Now()
	dur, err = s.vpFlowExecutor.SendAuthorizedResponse(ctx, authorizedResponse)
	s.perfInfo.SendAuthorizedResponse = dur
	s.perfInfo.VcsVPFlowDuration += dur
	if err != nil {
		return err
	}

	log.Println("Credentials shared with verifier")
	return nil
}

type VPFlowExecutor struct {
	tlsConfig                     *tls.Config
	ariesServices                 *ariesServices
	wallet                        Wallet
	walletToken                   string
	walletDidID                   []string
	walletDidKeyID                []string
	walletSignType                vcs.SignatureType
	requestObject                 *RequestObject
	requestPresentation           []*verifiable.Presentation
	requestPresentationSubmission *presexch.PresentationSubmission

	skipSchemaValidation bool
	httpClient           *http.Client
	walletDidTypes       []string
}

func (s *Service) NewVPFlowExecutor(skipSchemaValidation bool) *VPFlowExecutor {
	return &VPFlowExecutor{
		tlsConfig:            s.vcProviderConf.TLS,
		ariesServices:        s.ariesServices,
		wallet:               s.wallet,
		walletToken:          s.vcProviderConf.WalletParams.Token,
		walletDidID:          s.vcProviderConf.WalletParams.DidID,
		walletDidKeyID:       s.vcProviderConf.WalletParams.DidKeyID,
		walletDidTypes:       s.vcProviderConf.WalletParams.DidTypes,
		walletSignType:       s.vcProviderConf.WalletParams.SignType,
		skipSchemaValidation: skipSchemaValidation,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: s.vcProviderConf.TLS,
			},
		},
	}
}

func (s *Service) GetVPFlowExecutor() *VPFlowExecutor {
	return s.vpFlowExecutor
}

func (e *VPFlowExecutor) InitiateInteraction(url, authToken string, body io.Reader) (*InitiateOIDC4VPResponse, error) {
	resp, err := httputil.HTTPSDo(http.MethodPost, url, "application/json", authToken, //nolint: bodyclose
		body, e.tlsConfig)
	if err != nil {
		return nil, err
	}

	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	result := &InitiateOIDC4VPResponse{}

	return result, json.Unmarshal(respBytes, result)
}

func (e *VPFlowExecutor) FetchRequestObject(authorizationRequest string) (string, time.Duration, error) {
	endpointURL := strings.TrimPrefix(authorizationRequest, "openid-vc://?request_uri=")

	st := time.Now()
	resp, err := httputil.HTTPSDo(http.MethodGet, endpointURL, "", "", nil, e.tlsConfig)
	dur := time.Since(st)
	if err != nil {
		return "", dur, err
	}
	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", dur, err
	}

	if resp.StatusCode != http.StatusOK {
		return "", dur, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return string(respBytes), dur, nil
}

func (e *VPFlowExecutor) RequestPresentations() []*verifiable.Presentation {
	return e.requestPresentation
}

func (e *VPFlowExecutor) RetrieveInteractionsClaim(url, authToken string) ([]byte, error) {
	resp, err := httputil.HTTPSDo(http.MethodGet, url, "application/json", authToken, //nolint: bodyclose
		nil, e.tlsConfig)
	if err != nil {
		return nil, err
	}
	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return respBytes, nil
}

func (e *VPFlowExecutor) VerifyAuthorizationRequestAndDecodeClaims(rawRequestObject string) error {
	jwtVerifier := jwt.NewVerifier(jwt.KeyResolverFunc(
		verifiable.NewVDRKeyResolver(e.ariesServices.vdrRegistry).PublicKeyFetcher()))

	rawData, err := verifyTokenSignature(rawRequestObject, jwtVerifier)
	if err != nil {
		return err
	}

	var requestObject *RequestObject
	if err = json.Unmarshal(rawData, &requestObject); err != nil {
		return fmt.Errorf("requestObject decode claims: %w", err)
	}

	e.requestObject = requestObject

	return nil
}

func verifyTokenSignature(rawJwt string, verifier jose.SignatureVerifier) ([]byte, error) {
	_, rawData, err := jwt.Parse(
		rawJwt,
		jwt.WithSignatureVerifier(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	return rawData, nil
}

func (e *VPFlowExecutor) QueryCredentialFromWalletSingleVP() error {
	if e.skipSchemaValidation && len(e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors) > 0 { // bypass
		oldScheme := e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors[0].Schema
		e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors[0].Schema = nil
		defer func() {
			e.requestObject.Claims.VPToken.PresentationDefinition.InputDescriptors[0].Schema = oldScheme
		}()
	}

	pdBytes, err := json.Marshal(e.requestObject.Claims.VPToken.PresentationDefinition)

	if err != nil {
		return fmt.Errorf("presentation definition marshal: %w", err)
	}

	// This query will always return one VP - so far no plans to change this
	vps, err := e.wallet.Query(pdBytes)

	if err != nil {
		return fmt.Errorf("query vc using presentation definition: %w", err)
	}

	vps[0].Context = []string{"https://www.w3.org/2018/credentials/v1"}

	e.requestPresentation = vps
	e.requestPresentationSubmission = vps[0].CustomFields["presentation_submission"].(*presexch.PresentationSubmission)

	return nil
}

func (e *VPFlowExecutor) QueryCredentialFromWalletMultiVP() error {
	pdBytes, err := json.Marshal(e.requestObject.Claims.VPToken.PresentationDefinition)

	if err != nil {
		return fmt.Errorf("presentation definition marshal: %w", err)
	}

	// This query will always return one VP - so far no plans to change this
	// We will only use this to get relevant credentials from wallet
	legacyVP, err := e.wallet.Query(pdBytes)
	if err != nil {
		return fmt.Errorf("query credentials from wallet: %w", err)
	}

	credentials, err := e.getCredentials(legacyVP[0].Credentials())
	if err != nil {
		return fmt.Errorf("failed to parse credentials from vp: %w", err)
	}

	// Create a list of verifiable presentations, with one presentation for each provided credential.
	vps, ps, err := e.requestObject.Claims.VPToken.PresentationDefinition.CreateVPArray(credentials, e.ariesServices.documentLoader, verifiable.WithJSONLDDocumentLoader(e.ariesServices.documentLoader))
	if err != nil {
		return fmt.Errorf("failed to create VP array from selected credentials: %w", err)
	}

	e.requestPresentation = vps
	e.requestPresentationSubmission = ps

	return nil
}

func (e *VPFlowExecutor) getIDTokenClaims(requestPresentationSubmission *presexch.PresentationSubmission) *IDTokenClaims {
	return &IDTokenClaims{
		VPToken: IDTokenVPToken{
			PresentationSubmission: requestPresentationSubmission,
		},
		Nonce: e.requestObject.Nonce,
		Exp:   time.Now().Unix() + 600,
		Iss:   "https://self-issued.me/v2/openid-vc",
		Aud:   e.requestObject.ClientID,
		Sub:   e.walletDidID[0],
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}
}

func (e *VPFlowExecutor) signIDTokenJWT(idToken *IDTokenClaims, signatureType vcs.SignatureType) (string, error) {
	idTokenJWS, err := signTokenJWT(idToken, e.walletDidKeyID[0], e.ariesServices.crypto, e.ariesServices.kms, signatureType)
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}

	return idTokenJWS, nil
}

func (e *VPFlowExecutor) CreateAuthorizedResponse(o ...RPConfigOverride) (string, error) {
	configRP, err := e.getRPConfig()
	if err != nil {
		return "", err
	}

	for _, f := range o {
		f(configRP)
	}

	var tokens []string

	for i, vp := range e.requestPresentation {
		delete(vp.CustomFields, "presentation_submission")

		var didID string

		didID, err = e.GetSubjectID(vp.Credentials())
		if err != nil {
			return "", err
		}

		didIDIndex := e.getDIDIndex(didID)
		didKeyID := e.walletDidKeyID[didIDIndex]
		signatureType := e.walletDidTypes[didIDIndex]

		var signedVPToken string

		switch configRP.supportedVPFormat {
		case vcs.Jwt:
			e.requestPresentationSubmission.DescriptorMap[i].Format = "jwt_vp"
			signedVPToken, err = e.signPresentationJWT(vp, e.walletSignType, didID, didKeyID)
		case vcs.Ldp:
			if lo.Contains(e.requestObject.Registration.VPFormats.LdpVP.ProofType, signatureType) {
				return "", fmt.Errorf("e.requestObject.Registration.VPFormats.LdpVP.ProofType does not support %v",
					signatureType)
			}
			e.requestPresentationSubmission.DescriptorMap[i].Format = "ldp_vp"
			signedVPToken, err = e.signPresentationLDP(vp, vcs.SignatureType(signatureType), didKeyID)
		}
		if err != nil {
			return "", fmt.Errorf("format %s sign VP: %w", configRP.supportedVPFormat, err)
		}

		tokens = append(tokens, signedVPToken)
	}

	tokensJSON := tokens[0]
	if len(tokens) > 1 {
		var tokensJSONBytes []byte

		tokensJSONBytes, err = json.Marshal(tokens)
		if err != nil {
			return "", fmt.Errorf("marshal tokens: %w", err)
		}

		tokensJSON = string(tokensJSONBytes)
	}

	var signedIDToken string

	signedIDToken, err = e.signIDTokenJWT(e.getIDTokenClaims(e.requestPresentationSubmission), e.walletSignType)
	if err != nil {
		return "", err
	}

	data := url.Values{}
	data.Set("id_token", signedIDToken)
	data.Set("vp_token", tokensJSON)
	data.Set("state", e.requestObject.State)

	return data.Encode(), nil
}

type RPConfig struct {
	supportedVPFormat, supportedVCFormat vcs.Format
	supportedSignatureType               vcs.SignatureType
}

func (e *VPFlowExecutor) getRPConfig() (*RPConfig, error) {
	config := &RPConfig{}

	roVPFormats := e.requestObject.Registration.VPFormats
	switch {
	case roVPFormats.JwtVP != nil:
		config.supportedVPFormat = vcs.Jwt
		config.supportedSignatureType = vcs.SignatureType(roVPFormats.JwtVP.Alg[0])
	case roVPFormats.LdpVP != nil:
		config.supportedVPFormat = vcs.Ldp
		config.supportedSignatureType = vcs.SignatureType(roVPFormats.LdpVP.ProofType[0])
	default:
		return nil, fmt.Errorf("RP supported VP format is not defiled, request object: %+v", roVPFormats)
	}

	switch {
	case roVPFormats.JwtVC != nil:
		config.supportedVCFormat = vcs.Jwt
	case roVPFormats.LdpVC != nil:
		config.supportedVCFormat = vcs.Ldp
	default:
		return nil, fmt.Errorf("RP supported VC format is not defiled, request object: %+v", roVPFormats)
	}

	return config, nil
}

func (e *VPFlowExecutor) signPresentationLDP(vp *verifiable.Presentation, signatureType vcs.SignatureType, didKeyID string) (string, error) {
	vcCryptoSigner := vccrypto.New(e.ariesServices.vdrRegistry, e.ariesServices.documentLoader)
	vp.Context = append(vp.Context, "https://w3id.org/security/suites/jws-2020/v1")

	signedVP, err := vcCryptoSigner.SignPresentation(
		&vc.Signer{
			Creator:                 didKeyID,
			KMSKeyID:                strings.Split(didKeyID, "#")[1],
			SignatureType:           signatureType,
			SignatureRepresentation: verifiable.SignatureProofValue,
			KMS: vcskms.GetAriesKeyManager(
				e.ariesServices.kms, e.ariesServices.crypto, vcskms.Local, noop.GetMetrics()),
		},
		vp,
		vccrypto.WithChallenge(e.requestObject.Nonce),
		vccrypto.WithDomain(e.requestObject.ClientID),
	)
	if err != nil {
		return "", fmt.Errorf("sign presentation LDP: %w", err)
	}

	var b []byte
	b, err = signedVP.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal signed VP: %w", err)
	}

	return string(b), nil
}

func (e *VPFlowExecutor) signPresentationJWT(vp *verifiable.Presentation, signatureType vcs.SignatureType, didID, didKeyID string) (string, error) {
	vpTokenBytes, err := json.Marshal(e.getJWTVPTokenClaims(vp, didID))
	if err != nil {
		return "", err
	}

	vpTokenJWS := strings.ReplaceAll(string(vpTokenBytes), `"type":"VerifiablePresentation"`, `"type":["VerifiablePresentation"]`)

	vpTokenJWS, err = signTokenJWT(vpTokenJWS, didKeyID, e.ariesServices.crypto, e.ariesServices.kms, signatureType)
	if err != nil {
		return "", fmt.Errorf("sign vp_token: %w", err)
	}

	return vpTokenJWS, nil
}

func (e *VPFlowExecutor) getJWTVPTokenClaims(vp *verifiable.Presentation, didID string) VPTokenClaims {
	nowSec := time.Now().Unix()

	return VPTokenClaims{
		VP:    vp,
		Nonce: e.requestObject.Nonce,
		Exp:   nowSec + 600,
		Iss:   didID,
		Aud:   e.requestObject.ClientID,
		Nbf:   nowSec,
		Iat:   nowSec,
		Jti:   uuid.NewString(),
	}
}

func (e *VPFlowExecutor) getCredentials(creds []interface{}) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	for _, cred := range creds {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}

		credentialParsed, err := verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(e.ariesServices.documentLoader))
		if err != nil {
			return nil, fmt.Errorf("fail to parse credential: %w", err)
		}

		credentials = append(credentials, credentialParsed)
	}

	return credentials, nil
}

func (e *VPFlowExecutor) getDIDIndex(did string) int {
	for index, walletDID := range e.walletDidID {
		if did == walletDID {
			return index
		}
	}

	return -1
}

func (e *VPFlowExecutor) GetSubjectID(creds []interface{}) (string, error) {
	subjectIDMap := make(map[string]bool)

	var subjectID string

	for _, cred := range creds {
		vcBytes, err := json.Marshal(cred)
		if err != nil {
			return "", err
		}

		vc, err := verifiable.ParseCredential(vcBytes,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(e.ariesServices.documentLoader))
		if err != nil {
			return "", fmt.Errorf("fail to parse credential: %w", err)
		}

		subjectID, err = verifiable.SubjectID(vc.Subject)
		if err != nil {
			return "", fmt.Errorf("failed to get subject ID: %w", err)
		}

		if vc.JWT != "" {
			// We use this strange code, because cred.JWTClaims(false) not take to account "sub" claim from jwt
			_, rawClaims, credErr := jwt.Parse(
				vc.JWT,
				jwt.WithSignatureVerifier(&noVerifier{}),
				jwt.WithIgnoreClaimsMapDecoding(true),
			)
			if credErr != nil {
				return "", fmt.Errorf("fail to parse credential as jwt: %w", credErr)
			}

			subjectID = fmt.Sprint(fastjson.GetString(rawClaims, "sub"))
		}

		subjectIDMap[subjectID] = true
	}

	if len(subjectIDMap) > 1 {
		fmt.Println("WARNING ... more than one subject ID found in VP")
	}

	return subjectID, nil
}

func signTokenJWT(claims interface{}, didKeyID string, crpt crypto.Crypto,
	km kms.KeyManager, signType vcs.SignatureType) (string, error) {

	kmsSigner, err := signer.NewKMSSigner(km, crpt, strings.Split(didKeyID, "#")[1], signType, nil)
	if err != nil {
		return "", fmt.Errorf("create kms signer: %w", err)
	}

	signerKeyID := didKeyID

	if strings.Contains(didKeyID, "did:key") {
		res, err := didkey.New().Read(strings.Split(didKeyID, "#")[0])
		if err != nil {
			return "", err
		}

		signerKeyID = res.DIDDocument.VerificationMethod[0].ID
	} else if strings.Contains(didKeyID, "did:jwk") {
		res, err := jwk.New().Read(strings.Split(didKeyID, "#")[0])
		if err != nil {
			return "", err
		}

		signerKeyID = res.DIDDocument.VerificationMethod[0].ID
	}

	token, err := jwt.NewSigned(claims, map[string]interface{}{"typ": "JWT"}, NewJWSSigner(signerKeyID,
		string(signType), kmsSigner))
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: sign token failed: %w", err)
	}

	tokenBytes, err := token.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("initiate oidc interaction: serialize token failed: %w", err)
	}

	return tokenBytes, nil
}

func (e *VPFlowExecutor) SendAuthorizedResponse(ctx context.Context, responseBody string) (time.Duration, error) {
	log.Printf("auth req: %s\n", responseBody)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		e.requestObject.RedirectURI,
		bytes.NewBuffer([]byte(responseBody)),
	)
	if err != nil {
		return 0, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := HttpClientFromContext(ctx, e.httpClient)
	st := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(st)

	if err != nil {
		return dur, err
	}

	defer httputil.CloseResponseBody(resp.Body)

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return dur, err
	}

	if resp.StatusCode != http.StatusOK {
		return dur, fmt.Errorf("expected status code %d but got status code %d with response body %s instead",
			http.StatusOK, resp.StatusCode, respBytes)
	}

	return dur, nil
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

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct{}

func (v noVerifier) Verify(_ jose.Headers, _, _, _ []byte) error {
	return nil
}
