/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc4vp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/kms-go/wrapper/api"
	didconfigclient "github.com/trustbloc/vc-go/didconfig/client"
	"github.com/trustbloc/vc-go/jwt"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

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
	linkedDomainsService = "LinkedDomains"
	tokenLifetimeSeconds = 600
)

type Flow struct {
	httpClient                     *http.Client
	documentLoader                 ld.DocumentLoader
	vdrRegistry                    vdrapi.Registry
	cryptoSuite                    api.Suite
	signer                         jose.Signer
	wallet                         *wallet.Wallet
	walletDID                      *did.DID
	requestURI                     string
	enableLinkedDomainVerification bool
	disableDomainMatching          bool
}

type provider interface {
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	CryptoSuite() api.Suite
	Wallet() *wallet.Wallet
}

func NewFlow(p provider, opts ...Opt) (*Flow, error) {
	o := &options{
		walletDIDIndex: len(p.Wallet().DIDs()) - 1,
	}

	for i := range opts {
		opts[i](o)
	}

	if _, err := url.Parse(o.requestURI); err != nil {
		return nil, fmt.Errorf("invalid request uri: %w", err)
	}

	if o.walletDIDIndex < 0 || o.walletDIDIndex >= len(p.Wallet().DIDs()) {
		return nil, fmt.Errorf("invalid wallet did index: %d", o.walletDIDIndex)
	}

	walletDIDInfo := p.Wallet().DIDs()[o.walletDIDIndex]

	walletDID, err := did.Parse(walletDIDInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("parse wallet did: %w", err)
	}

	docResolution, err := p.VDRegistry().Resolve(walletDID.String())
	if err != nil {
		return nil, fmt.Errorf("resolve wallet did: %w", err)
	}

	signer, err := p.CryptoSuite().FixedKeyMultiSigner(walletDIDInfo.KeyID)
	if err != nil {
		return nil, fmt.Errorf("create signer for key %s: %w", walletDIDInfo.KeyID, err)
	}

	signatureType := p.Wallet().SignatureType()

	jwsSigner := jwssigner.NewJWSSigner(
		docResolution.DIDDocument.VerificationMethod[0].ID,
		string(signatureType),
		kmssigner.NewKMSSigner(signer, signatureType, nil),
	)

	return &Flow{
		httpClient:                     p.HTTPClient(),
		documentLoader:                 p.DocumentLoader(),
		vdrRegistry:                    p.VDRegistry(),
		cryptoSuite:                    p.CryptoSuite(),
		signer:                         jwsSigner,
		wallet:                         p.Wallet(),
		walletDID:                      walletDID,
		requestURI:                     o.requestURI,
		enableLinkedDomainVerification: o.enableLinkedDomainVerification,
		disableDomainMatching:          o.disableDomainMatching,
	}, nil
}

func (f *Flow) Run(ctx context.Context) error {
	requestObject, err := f.fetchRequestObject(ctx)
	if err != nil {
		return err
	}

	if f.enableLinkedDomainVerification {
		if err = f.runLinkedDomainVerification(requestObject.ClientID); err != nil {
			return err
		}
	}

	credentials, err := f.queryWallet(requestObject.Claims.VPToken.PresentationDefinition)
	if err != nil {
		return fmt.Errorf("query wallet: %w", err)
	}

	if !f.disableDomainMatching {
		for i := len(credentials) - 1; i >= 0; i-- {
			credential := credentials[i]
			if !sameDIDWebDomain(credential.Contents().Issuer.ID, requestObject.ClientID) {
				credentials = append(credentials[:i], credentials[i+1:]...)
			}
		}
	}

	if err = f.sendAuthorizationResponse(ctx, requestObject, credentials); err != nil {
		return fmt.Errorf("send authorization response: %w", err)
	}

	return nil
}

func (f *Flow) fetchRequestObject(ctx context.Context) (*RequestObject, error) {
	slog.Info("fetching request object",
		"uri", f.requestURI,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.requestURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request object request: %w", err)
	}

	req.Header.Add("content-type", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get to request uri: %w", err)
	}

	var b []byte

	if b, err = io.ReadAll(resp.Body); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"fetch request object: status %s and body %s",
			resp.Status,
			string(b),
		)
	}

	_ = resp.Body.Close()

	jwtVerifier := jwt.NewVerifier(
		jwt.KeyResolverFunc(
			verifiable.NewVDRKeyResolver(f.vdrRegistry).PublicKeyFetcher(),
		),
	)

	_, b, err = jwt.Parse(
		string(b),
		jwt.WithSignatureVerifier(jwtVerifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse request object jwt: %w", err)
	}

	var requestObject *RequestObject

	if err = json.Unmarshal(b, &requestObject); err != nil {
		return nil, fmt.Errorf("unmarshal request object: %w", err)
	}

	return requestObject, nil
}

type serviceEndpoint struct {
	Origins []string `json:"origins"`
}

func (f *Flow) runLinkedDomainVerification(clientDID string) error {
	slog.Info("running linked domain verification",
		"did", clientDID,
	)

	docResolution, err := f.vdrRegistry.Resolve(clientDID)
	if err != nil {
		return fmt.Errorf("resolve client did: %w", err)
	}

	for _, service := range docResolution.DIDDocument.Service {
		serviceType := getServiceType(service.Type)
		if serviceType != linkedDomainsService {
			continue
		}

		b, marshalErr := service.ServiceEndpoint.MarshalJSON()
		if marshalErr != nil {
			return fmt.Errorf("get LinkedDomains service endpoint: %w", marshalErr)
		}

		svc := serviceEndpoint{}

		if err = json.Unmarshal(b, &svc); err != nil {
			return err
		}

		client := didconfigclient.New(
			didconfigclient.WithJSONLDDocumentLoader(f.documentLoader),
			didconfigclient.WithVDRegistry(f.vdrRegistry),
			didconfigclient.WithHTTPClient(f.httpClient),
		)

		if err = client.VerifyDIDAndDomain(clientDID, strings.TrimSuffix(svc.Origins[0], "/")); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("no LinkedDomains services defined for %s", clientDID)
}

func getServiceType(serviceType interface{}) string {
	var val string

	switch t := serviceType.(type) {
	case string:
		val = t
	case []string:
		if len(t) > 0 {
			val = t[0]
		}
	case []interface{}:
		if len(t) > 0 {
			if str, ok := t[0].(string); ok {
				val = str
			}
		}
	}

	return val
}

func (f *Flow) queryWallet(pd *presexch.PresentationDefinition) ([]*verifiable.Credential, error) {
	slog.Info("querying wallet")

	b, err := json.Marshal(pd)
	if err != nil {
		return nil, fmt.Errorf("marshal presentation definition: %w", err)
	}

	presentations, err := f.wallet.Query(b)
	if err != nil {
		return nil, err
	}

	if len(presentations) == 0 || len(presentations[0].Credentials()) == 0 {
		return nil, fmt.Errorf("no matching credentials found")
	}

	return presentations[0].Credentials(), nil
}

func sameDIDWebDomain(did1, did2 string) bool {
	if strings.HasPrefix(did1, "did:web:") && strings.HasPrefix(did2, "did:web:") {
		if i := strings.Index(did1, "."); i != -1 {
			if j := strings.Index(did2, "."); j != -1 {
				return strings.EqualFold(did1[:i], did2[:j])
			}
		}
	}

	return false
}

func (f *Flow) sendAuthorizationResponse(
	ctx context.Context,
	requestObject *RequestObject,
	credentials []*verifiable.Credential,
) error {
	slog.Info("sending authorization response",
		"redirect_uri", requestObject.RedirectURI,
	)

	presentationDefinition := requestObject.Claims.VPToken.PresentationDefinition

	var (
		vpToken                string
		presentationSubmission *presexch.PresentationSubmission
	)

	if len(credentials) == 1 {
		credential := credentials[0]

		presentation, err := presentationDefinition.CreateVP(
			[]*verifiable.Credential{credential},
			f.documentLoader,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(f.documentLoader),
		)
		if err != nil {
			return fmt.Errorf("create vp: %w", err)
		}

		var ok bool

		presentationSubmission, ok = presentation.CustomFields["presentation_submission"].(*presexch.PresentationSubmission)
		if !ok {
			return fmt.Errorf("missing or invalid presentation_submission")
		}

		vpFormats := requestObject.Registration.VPFormats

		if vpFormats.JwtVP != nil {
			presentationSubmission.DescriptorMap[0].Format = "jwt_vp"
		} else if vpFormats.LdpVP != nil {
			presentationSubmission.DescriptorMap[0].Format = "ldp_vp"
		}

		vpToken, err = f.createVPToken(presentation, requestObject)
		if err != nil {
			return fmt.Errorf("create vp token: %w", err)
		}
	} else if len(credentials) > 1 {
		var (
			vpTokens      []string
			presentations []*verifiable.Presentation
			err           error
		)

		presentations, presentationSubmission, err = presentationDefinition.CreateVPArray(
			credentials,
			f.documentLoader,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(f.documentLoader),
		)
		if err != nil {
			return fmt.Errorf("create vp array: %w", err)
		}

		for i, presentation := range presentations {
			delete(presentation.CustomFields, "presentation_submission")

			vpFormats := requestObject.Registration.VPFormats

			if vpFormats.JwtVP != nil {
				presentationSubmission.DescriptorMap[i].Format = "jwt_vp"
			} else if vpFormats.LdpVP != nil {
				presentationSubmission.DescriptorMap[i].Format = "ldp_vp"
			}

			token, createErr := f.createVPToken(presentation, requestObject)
			if createErr != nil {
				return fmt.Errorf("create vp token: %w", createErr)
			}

			vpTokens = append(vpTokens, token)
		}

		b, err := json.Marshal(vpTokens)
		if err != nil {
			return fmt.Errorf("marshal vp tokens: %w", err)
		}

		vpToken = string(b)
	} else {
		return fmt.Errorf("no matching credentials found")
	}

	idToken, err := f.createIDToken(presentationSubmission, requestObject.ClientID, requestObject.Nonce)
	if err != nil {
		return fmt.Errorf("create id token: %w", err)
	}

	v := url.Values{
		"id_token": {idToken},
		"vp_token": {vpToken},
		"state":    {requestObject.State},
	}

	return f.postAuthorizationResponse(ctx, requestObject.RedirectURI, []byte(v.Encode()))
}

func (f *Flow) createVPToken(
	presentation *verifiable.Presentation,
	requestObject *RequestObject,
) (string, error) {
	credential := presentation.Credentials()[0]

	subjectDID, err := verifiable.SubjectID(credential.Contents().Subject)
	if err != nil {
		return "", fmt.Errorf("get subject did: %w", err)
	}

	vpFormats := requestObject.Registration.VPFormats

	switch {
	case vpFormats.JwtVP != nil:
		return f.signPresentationJWT(
			presentation,
			subjectDID,
			requestObject.ClientID,
			requestObject.Nonce,
		)
	case vpFormats.LdpVP != nil:
		return f.signPresentationLDP(
			presentation,
			vcs.SignatureType(vpFormats.LdpVP.ProofType[0]),
			subjectDID,
			requestObject.ClientID,
			requestObject.Nonce,
		)
	default:
		return "", fmt.Errorf("no supported vp formats: %v", vpFormats)
	}
}

func (f *Flow) signPresentationJWT(
	vp *verifiable.Presentation,
	signerDID, clientID, nonce string,
) (string, error) {
	docResolution, err := f.vdrRegistry.Resolve(signerDID)
	if err != nil {
		return "", fmt.Errorf("resolve signer did: %w", err)
	}

	verificationMethod := docResolution.DIDDocument.VerificationMethod[0]

	var kmsKeyID string

	for _, didInfo := range f.wallet.DIDs() {
		if didInfo.ID == signerDID {
			kmsKeyID = didInfo.KeyID
			break
		}
	}

	signer, err := f.cryptoSuite.FixedKeyMultiSigner(kmsKeyID)
	if err != nil {
		return "", fmt.Errorf("create signer for key %s: %w", kmsKeyID, err)
	}

	kmsSigner := kmssigner.NewKMSSigner(signer, f.wallet.SignatureType(), nil)

	claims := VPTokenClaims{
		VP:    vp,
		Nonce: nonce,
		Exp:   time.Now().Unix() + tokenLifetimeSeconds,
		Iss:   signerDID,
		Aud:   clientID,
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}

	signedJWT, err := jwt.NewSigned(
		claims,
		map[string]interface{}{"typ": "JWT"},
		jwssigner.NewJWSSigner(
			verificationMethod.ID,
			string(f.wallet.SignatureType()),
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

func (f *Flow) signPresentationLDP(
	vp *verifiable.Presentation,
	signatureType vcs.SignatureType,
	signerDID, clientID, nonce string,
) (string, error) {
	cryptoSigner := vccrypto.New(f.vdrRegistry, f.documentLoader)

	vp.Context = append(vp.Context, "https://w3id.org/security/suites/jws-2020/v1")

	docResolution, err := f.vdrRegistry.Resolve(signerDID)
	if err != nil {
		return "", fmt.Errorf("resolve signer did: %w", err)
	}

	verificationMethod := docResolution.DIDDocument.VerificationMethod[0]

	var kmsKeyID string

	for _, didInfo := range f.wallet.DIDs() {
		if didInfo.ID == signerDID {
			kmsKeyID = didInfo.KeyID
			break
		}
	}

	signedVP, err := cryptoSigner.SignPresentation(
		&vc.Signer{
			Creator:                 verificationMethod.ID,
			KMSKeyID:                kmsKeyID,
			SignatureType:           signatureType,
			SignatureRepresentation: verifiable.SignatureProofValue,
			KMS:                     vcskms.GetAriesKeyManager(f.cryptoSuite, vcskms.Local, noop.GetMetrics()),
		},
		vp,
		vccrypto.WithChallenge(nonce),
		vccrypto.WithDomain(clientID),
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

func (f *Flow) createIDToken(
	presentationSubmission *presexch.PresentationSubmission,
	clientID, nonce string,
) (string, error) {
	idToken := &IDTokenClaims{
		VPToken: IDTokenVPToken{
			PresentationSubmission: presentationSubmission,
		},
		Nonce: nonce,
		Exp:   time.Now().Unix() + tokenLifetimeSeconds,
		Iss:   "https://self-issued.me/v2/openid-vc",
		Aud:   clientID,
		Sub:   f.walletDID.String(),
		Nbf:   time.Now().Unix(),
		Iat:   time.Now().Unix(),
		Jti:   uuid.NewString(),
	}

	signedIDToken, err := jwt.NewSigned(
		idToken,
		map[string]interface{}{"typ": "JWT"},
		f.signer,
	)
	if err != nil {
		return "", fmt.Errorf("create signed id token: %w", err)
	}

	idTokenJSON, err := signedIDToken.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serialize signed id token: %w", err)
	}

	return idTokenJSON, nil
}

func (f *Flow) postAuthorizationResponse(ctx context.Context, redirectURI string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, redirectURI, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("new authorization response request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post to redirect uri: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Error("failed to close response body", "err", closeErr)
		}
	}()

	var b []byte

	if resp.StatusCode != http.StatusOK {
		if b, err = io.ReadAll(resp.Body); err != nil {
			return err
		}

		return fmt.Errorf(
			"response from redirect uri: status %s and body %s",
			resp.Status,
			string(b),
		)
	}

	slog.Info("credential presented successfully")

	return nil
}

type options struct {
	walletDIDIndex                 int
	requestURI                     string
	enableLinkedDomainVerification bool
	disableDomainMatching          bool
}

type Opt func(opts *options)

func WithWalletDIDIndex(idx int) Opt {
	return func(opts *options) {
		opts.walletDIDIndex = idx
	}
}

func WithRequestURI(uri string) Opt {
	return func(opts *options) {
		opts.requestURI = uri
	}
}

func WithLinkedDomainVerification() Opt {
	return func(opts *options) {
		opts.enableLinkedDomainVerification = true
	}
}

func WithDomainMatchingDisabled() Opt {
	return func(opts *options) {
		opts.disableDomainMatching = true
	}
}
