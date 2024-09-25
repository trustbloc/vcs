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
	"reflect"
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
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/presentation"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/attestation"
	jwssigner "github.com/trustbloc/vcs/component/wallet-cli/pkg/signer"
	"github.com/trustbloc/vcs/component/wallet-cli/pkg/wallet"
	kmssigner "github.com/trustbloc/vcs/pkg/kms/signer"
)

const (
	linkedDomainsService = "LinkedDomains"

	scopeOpenID              = "openid"
	customScopeTimeDetails   = "timedetails"
	customScopeWalletDetails = "walletdetails"
	tokenLifetimeSeconds     = 600
)

type AttestationService interface {
	GetAttestation(ctx context.Context, req attestation.GetAttestationRequest) (string, error)
}

type TrustRegistry interface {
	ValidateVerifier(
		ctx context.Context,
		verifierDID,
		verifierDomain string,
		credentials []*verifiable.Credential,
	) (bool, error)
}

type Flow struct {
	httpClient                     *http.Client
	documentLoader                 ld.DocumentLoader
	vdrRegistry                    vdrapi.Registry
	cryptoSuite                    api.Suite
	signer                         jose.Signer
	attestationService             AttestationService
	trustRegistry                  TrustRegistry
	wallet                         *wallet.Wallet
	walletDID                      *did.DID
	requestURI                     string
	enableLinkedDomainVerification bool
	disableDomainMatching          bool
	disableSchemaValidation        bool
	perfInfo                       *PerfInfo
	useMultiVPs                    bool
	attachments                    map[string]string
}

type provider interface {
	HTTPClient() *http.Client
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	CryptoSuite() api.Suite
	AttestationService() AttestationService
	TrustRegistry() TrustRegistry
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
		attestationService:             p.AttestationService(),
		trustRegistry:                  p.TrustRegistry(),
		wallet:                         p.Wallet(),
		walletDID:                      walletDID,
		requestURI:                     o.requestURI,
		enableLinkedDomainVerification: o.enableLinkedDomainVerification,
		disableDomainMatching:          o.disableDomainMatching,
		disableSchemaValidation:        o.disableSchemaValidation,
		useMultiVPs:                    o.useMultiVPs,
		perfInfo:                       &PerfInfo{},
		attachments:                    o.attachments,
	}, nil
}

func (f *Flow) Run(ctx context.Context) error {
	totalFlowStart := time.Now()
	defer func() {
		f.perfInfo.VcsVPFlowDuration = time.Since(totalFlowStart)
	}()

	slog.Info("Running OIDC4VP flow",
		"wallet_did", f.walletDID.String(),
		"request_uri", f.requestURI,
		"enable_linked_domain_verification", f.enableLinkedDomainVerification,
		"disable_domain_matching", f.disableDomainMatching,
		"disable_schema_validation", f.disableSchemaValidation,
	)

	requestObject, err := f.fetchRequestObject(ctx)
	if err != nil {
		return err
	}

	if f.enableLinkedDomainVerification {
		if err = f.runLinkedDomainVerification(requestObject.ClientID); err != nil {
			return err
		}
	}

	var pd presexch.PresentationDefinition

	rawPD, err := json.Marshal(requestObject.PresentationDefinition)
	if err != nil {
		return fmt.Errorf("marshal presentation definition: %w", err)
	}

	if err = json.Unmarshal(rawPD, &pd); err != nil {
		return fmt.Errorf("unmarshal presentation definition: %w", err)
	}

	if f.disableSchemaValidation && len(pd.InputDescriptors) > 0 {
		pd.InputDescriptors[0].Schema = nil
		requestObject.PresentationDefinition.InputDescriptors[0].Schema = nil
	}

	vps, presentationSubmission, err := f.queryWallet(&pd, requestObject.ClientMetadata.VPFormats)
	if err != nil {
		if strings.Contains(err.Error(), "no matching credentials found") {
			// Send wallet notification no_match_found.
			v := url.Values{}

			v.Add("error", "access_denied")
			v.Add("error_description", "no_match_found")
			v.Add("state", requestObject.State)

			if e := f.postAuthorizationResponse(ctx, requestObject.ResponseURI, []byte(v.Encode())); e != nil {
				slog.Error("failed to send wallet notification", "err", e)
			}
		}

		return fmt.Errorf("query wallet: %w", err)
	}

	vpFormats := requestObject.ClientMetadata.VPFormats

	for i := range presentationSubmission.DescriptorMap {
		if vpFormats.JwtVP != nil {
			presentationSubmission.DescriptorMap[i].Format = "jwt_vp"
		} else if vpFormats.LdpVP != nil {
			presentationSubmission.DescriptorMap[i].Format = "ldp_vp"
		} else if vpFormats.CwtVP != nil {
			presentationSubmission.DescriptorMap[i].Format = "cwt_vp"
		}
	}

	var credentials []*verifiable.Credential

	for _, vp := range vps {
		vpCredentials := vp.Credentials()

		if !f.disableDomainMatching {
			for i := len(vpCredentials) - 1; i >= 0; i-- {
				credential := vpCredentials[i]
				if !sameDIDWebDomain(credential.Contents().Issuer.ID, requestObject.ClientID) {
					vpCredentials = append(vpCredentials[:i], vpCredentials[i+1:]...)
				}
			}
		}

		credentials = append(credentials, vpCredentials...)
	}

	var attestationRequired bool

	if f.trustRegistry != nil && !reflect.ValueOf(f.trustRegistry).IsNil() {
		attestationRequired, err = f.trustRegistry.ValidateVerifier(ctx, requestObject.ClientID, "", credentials)
		if err != nil {
			return fmt.Errorf("validate verifier: %w", err)
		}
	}

	if err = f.sendAuthorizationResponse(
		ctx,
		requestObject,
		vps,
		presentationSubmission,
		attestationRequired,
	); err != nil {
		return fmt.Errorf("send authorization response: %w", err)
	}

	return nil
}

func (f *Flow) fetchRequestObject(ctx context.Context) (*RequestObject, error) {
	slog.Info("Fetching request object",
		"uri", f.requestURI,
	)

	start := time.Now()

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

	f.perfInfo.FetchRequestObject = time.Since(start)

	start = time.Now()
	defer func() {
		f.perfInfo.VerifyAuthorizationRequest = time.Since(start)
	}()

	jwtVerifier := defaults.NewDefaultProofChecker(
		vermethod.NewVDRResolver(f.vdrRegistry),
	)

	_, b, err = jwt.ParseAndCheckProof(
		string(b),
		jwtVerifier, true,
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
	slog.Info("Running linked domain verification",
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

func (f *Flow) queryWallet(
	pd *presexch.PresentationDefinition,
	vpFormat *presexch.Format,
) ([]*verifiable.Presentation, *presexch.PresentationSubmission, error) {
	slog.Info("Querying wallet")

	start := time.Now()
	defer func() {
		f.perfInfo.QueryCredentialFromWallet = time.Since(start)
	}()

	b, err := json.Marshal(pd)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal presentation definition: %w", err)
	}

	presentations, submission, err := f.wallet.Query(b, vpFormat.JwtVP != nil, f.useMultiVPs)
	if err != nil {
		return nil, nil, err
	}

	if len(presentations) == 0 || len(presentations[0].Credentials()) == 0 {
		return nil, nil, fmt.Errorf("no matching credentials found")
	}

	return presentations, submission, nil
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
	presentations []*verifiable.Presentation,
	presentationSubmission *presexch.PresentationSubmission,
	attestationRequired bool,
) error {
	slog.Info("Sending authorization response",
		"response_uri", requestObject.ResponseURI,
	)

	start := time.Now()

	v := url.Values{}

	idToken, err := f.createIDToken(
		ctx,
		requestObject.ClientID,
		requestObject.Nonce,
		requestObject.Scope,
		attestationRequired,
		f.attachments,
	)
	if err != nil {
		return fmt.Errorf("create id token: %w", err)
	}

	v.Add("id_token", idToken)

	vpTokens, err := f.CreateVPToken(presentations, requestObject)
	if err != nil {
		return fmt.Errorf("create vp token: %w", err)
	}

	if len(vpTokens) == 1 {
		v.Add("vp_token", vpTokens[0])
	} else {
		b, marshalErr := json.Marshal(vpTokens)
		if marshalErr != nil {
			return fmt.Errorf("marshal vp tokens: %w", marshalErr)
		}

		v.Add("vp_token", string(b))
	}

	presentationSubmissionJSON, err := json.Marshal(presentationSubmission)
	if err != nil {
		return fmt.Errorf("marshal presentation submission: %w", err)
	}

	v.Add("presentation_submission", string(presentationSubmissionJSON))
	v.Add("state", requestObject.State)

	f.perfInfo.CreateAuthorizedResponse = time.Since(start)

	return f.postAuthorizationResponse(ctx, requestObject.ResponseURI, []byte(v.Encode()))
}

func (f *Flow) CreateVPToken(
	presentations []*verifiable.Presentation,
	requestObject *RequestObject,
) ([]string, error) {
	return presentation.CreateVPToken(presentations, &presentation.CreateVpTokenRequest{
		ClientID:       requestObject.ClientID,
		Nonce:          requestObject.Nonce,
		VPFormats:      requestObject.ClientMetadata.VPFormats,
		Wallet:         f.wallet,
		CryptoSuite:    f.cryptoSuite,
		VdrRegistry:    f.vdrRegistry,
		DocumentLoader: f.documentLoader,
	})
}

func (f *Flow) createIDToken(
	ctx context.Context,
	clientID string,
	nonce string,
	requestObjectScope string,
	attestationRequired bool,
	attachments map[string]string,
) (string, error) {
	scopeAdditionalClaims, err := extractCustomScopeClaims(requestObjectScope)
	if err != nil {
		return "", fmt.Errorf("extractAdditionalClaims: %w", err)
	}

	idToken := &IDTokenClaims{
		ScopeAdditionalClaims: scopeAdditionalClaims,
		Nonce:                 nonce,
		Exp:                   time.Now().Unix() + tokenLifetimeSeconds,
		Iss:                   "https://self-issued.me/v2/openid-vc",
		Aud:                   clientID,
		Sub:                   f.walletDID.String(),
		Nbf:                   time.Now().Unix(),
		Iat:                   time.Now().Unix(),
		Jti:                   uuid.NewString(),
		Attachments:           attachments,
	}

	if attestationRequired {
		var jwtVP string

		jwtVP, err = f.attestationService.GetAttestation(ctx, attestation.GetAttestationRequest{})
		if err != nil {
			return "", fmt.Errorf("get attestation: %w", err)
		}

		idToken.AttestationVP = jwtVP
	}

	signedIDToken, err := jwt.NewJoseSigned(
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

func extractCustomScopeClaims(requestObjectScope string) (map[string]Claims, error) {
	chunks := strings.Split(requestObjectScope, "+")
	if len(chunks) == 1 {
		return nil, nil
	}

	claimsData := make(map[string]Claims, len(chunks)-1)

	for _, scope := range chunks {
		switch scope {
		case scopeOpenID:
			// scopeOpenID is a required specification scope, so no additional claims for this case.
			continue
		case customScopeTimeDetails:
			claimsData[scope] = Claims{
				"timestamp": time.Now().Format(time.RFC3339),
				"uuid":      uuid.NewString(),
			}
		case customScopeWalletDetails:
			claimsData[scope] = Claims{
				"wallet_version": "1.0",
				"uuid":           uuid.NewString(),
			}
		default:
			return nil, fmt.Errorf("unexpected custom scope \"%s\" supplied", chunks[1])
		}
	}

	return claimsData, nil
}

func (f *Flow) postAuthorizationResponse(ctx context.Context, responseURI string, body []byte) error {
	slog.Info("Sending authorization response",
		"response_uri", responseURI,
	)

	start := time.Now()
	defer func() {
		f.perfInfo.SendAuthorizedResponse = time.Since(start)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURI, bytes.NewBuffer(body))
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

	slog.Info("Credential presented successfully")

	return nil
}

func (f *Flow) PerfInfo() *PerfInfo {
	return f.perfInfo
}

type options struct {
	walletDIDIndex                 int
	requestURI                     string
	enableLinkedDomainVerification bool
	disableDomainMatching          bool
	disableSchemaValidation        bool
	useMultiVPs                    bool
	attachments                    map[string]string
}

type Opt func(opts *options)

func WithWalletDIDIndex(idx int) Opt {
	return func(opts *options) {
		opts.walletDIDIndex = idx
	}
}

func WithAttachments(attachments map[string]string) func(opts *options) {
	return func(opts *options) {
		opts.attachments = attachments
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

func WithSchemaValidationDisabled() Opt {
	return func(opts *options) {
		opts.disableSchemaValidation = true
	}
}

func WithMultiVPs() Opt {
	return func(opts *options) {
		opts.useMultiVPs = true
	}
}
