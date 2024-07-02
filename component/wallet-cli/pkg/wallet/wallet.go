/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/piprate/json-gold/ld"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/spi/storage"
	"github.com/trustbloc/kms-go/wrapper/api"
	"github.com/trustbloc/vc-go/presexch"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/trustbloc/vcs/component/wallet-cli/internal/vdrutil"
	vcs "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

const (
	credentialsStore = "wallet:credentials"
	credentialTag    = "credential"

	configStore      = "wallet:config"
	signatureTypeKey = "signatureType"
	didsKey          = "dids"
	nameKey          = "name"
	versionKey       = "version"
	walletTypeKey    = "walletType"
	complianceKey    = "compliance"
)

type DIDInfo struct {
	ID      string         `json:"id"`
	KeyID   string         `json:"key_id"`
	KeyType kmsapi.KeyType `json:"key_type"`
}

type Wallet struct {
	store          storage.Store
	documentLoader ld.DocumentLoader
	mu             sync.RWMutex
	signatureType  vcs.SignatureType
	dids           []*DIDInfo
	name           string
	version        string
	walletType     string
	compliance     string
}

type provider interface {
	StorageProvider() storage.Provider
	DocumentLoader() ld.DocumentLoader
	VDRegistry() vdrapi.Registry
	KeyCreator() api.RawKeyCreator
}

type options struct {
	keyType    kmsapi.KeyType
	newDIDs    []string
	name       string
	version    string
	walletType string
	compliance string
}

type Opt func(opts *options)

func New(p provider, opts ...Opt) (*Wallet, error) {
	o := &options{
		newDIDs:    make([]string, 0),
		name:       "wallet-cli",
		version:    "0.1",
		walletType: "system_pin",
	}

	for i := range opts {
		opts[i](o)
	}

	configurationStore, err := p.StorageProvider().OpenStore(configStore)
	if err != nil {
		return nil, fmt.Errorf("open config store: %w", err)
	}

	v, err := configurationStore.Get(nameKey)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get name: %w", err)
		}

		if err = configurationStore.Put(nameKey, []byte(o.name)); err != nil {
			return nil, fmt.Errorf("put name: %w", err)
		}
	} else {
		o.name = string(v)
	}

	v, err = configurationStore.Get(versionKey)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get version: %w", err)
		}

		if err = configurationStore.Put(versionKey, []byte(o.version)); err != nil {
			return nil, fmt.Errorf("put version: %w", err)
		}
	} else {
		o.version = string(v)
	}

	v, err = configurationStore.Get(walletTypeKey)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get authentication method: %w", err)
		}

		if err = configurationStore.Put(walletTypeKey, []byte(o.walletType)); err != nil {
			return nil, fmt.Errorf("put authentication method: %w", err)
		}
	} else {
		o.walletType = string(v)
	}

	v, err = configurationStore.Get(complianceKey)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get authentication method: %w", err)
		}

		if err = configurationStore.Put(complianceKey, []byte(o.compliance)); err != nil {
			return nil, fmt.Errorf("put authentication method: %w", err)
		}
	} else {
		o.compliance = string(v)
	}

	var (
		updateDIDs,
		updateSignatureType bool
	)

	var signatureType vcs.SignatureType

	b, err := configurationStore.Get(signatureTypeKey)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get signature type: %w", err)
		}
	} else {
		signatureType = vcs.SignatureType(b)
	}

	if o.keyType != "" {
		var st vcs.SignatureType

		if st, err = mapToSignatureType(o.keyType); err != nil {
			return nil, err
		}

		if signatureType == "" {
			signatureType = st
			updateSignatureType = true
		} else if signatureType != st {
			return nil, fmt.Errorf("wallet initialized to support signature type %s", signatureType)
		}
	}

	if signatureType == "" {
		return nil, fmt.Errorf("wallet not initialized (signature type not set), please run 'create' command")
	}

	dids := make([]*DIDInfo, 0)

	b, err = configurationStore.Get(didsKey)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get dids: %w", err)
		}
	} else {
		if err = json.Unmarshal(b, &dids); err != nil {
			return nil, fmt.Errorf("unmarshal dids: %w", err)
		}
	}

	if len(dids) == 0 && len(o.newDIDs) == 0 {
		return nil, fmt.Errorf("wallet not initialized, please run 'create' command")
	}

	var keyType kmsapi.KeyType

	if keyType, err = mapToKeyType(signatureType); err != nil {
		return nil, err
	}

	for _, method := range o.newDIDs {
		res, createErr := vdrutil.DefaultVdrUtil.Create(
			method,
			keyType,
			p.VDRegistry(),
			p.KeyCreator(),
		)
		if createErr != nil {
			return nil, fmt.Errorf("create did: %w", createErr)
		}

		dids = append(dids, &DIDInfo{
			ID:      res.DidID,
			KeyID:   strings.Split(res.KeyID, "#")[1],
			KeyType: keyType,
		})

		updateDIDs = true
	}

	if updateDIDs {
		b, err = json.Marshal(dids)
		if err != nil {
			return nil, fmt.Errorf("marshal dids: %w", err)
		}

		if err = configurationStore.Put(didsKey, b); err != nil {
			return nil, fmt.Errorf("put dids: %w", err)
		}
	}

	if updateSignatureType {
		if err = configurationStore.Put(signatureTypeKey, []byte(signatureType)); err != nil {
			return nil, fmt.Errorf("put signature type: %w", err)
		}
	}

	store, err := p.StorageProvider().OpenStore(credentialsStore)
	if err != nil {
		return nil, fmt.Errorf("open credential store: %w", err)
	}

	return &Wallet{
		store:          store,
		documentLoader: p.DocumentLoader(),
		signatureType:  signatureType,
		dids:           dids,
		name:           o.name,
		version:        o.version,
		walletType:     o.walletType,
		compliance:     o.compliance,
	}, nil
}

func mapToSignatureType(kt kmsapi.KeyType) (vcs.SignatureType, error) {
	switch kt {
	case kmsapi.ED25519Type:
		return vcs.EdDSA, nil
	case kmsapi.ECDSAP256TypeDER:
		return vcs.ES256, nil
	case kmsapi.ECDSAP384TypeDER:
		return vcs.ES384, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", kt)
	}
}

func mapToKeyType(st vcs.SignatureType) (kmsapi.KeyType, error) {
	switch st {
	case vcs.EdDSA:
		return kmsapi.ED25519Type, nil
	case vcs.ES256:
		return kmsapi.ECDSAP256TypeDER, nil
	case vcs.ES384:
		return kmsapi.ECDSAP384TypeDER, nil
	default:
		return "", fmt.Errorf("unsupported signature type: %s", st)
	}
}

// Open opens a wallet.
func (w *Wallet) Open(passphrase string) string {
	return "token"
}

// Close closes a wallet.
func (w *Wallet) Close() bool {
	return true
}

// Add adds a marshalled credential to the wallet.
func (w *Wallet) Add(vc json.RawMessage, key string) error {
	if key == "" {
		var err error
		key, err = getContentID(vc)
		if err != nil {
			return err
		}
	}

	slog.Info("Add vc to store", "keyID", key)

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.store.Put(key, vc, storage.Tag{Name: credentialTag}); err != nil {
		return err
	}

	return nil
}

type contentID struct {
	ID string `json:"id"`
}

func getContentID(content json.RawMessage) (string, error) {
	key, err := getJWTContentID(string(content))
	if err == nil && strings.TrimSpace(key) != "" {
		return key, nil
	}

	var cid contentID
	if err = json.Unmarshal(content, &cid); err != nil {
		return "", fmt.Errorf("failed to read content to be saved : %w", err)
	}

	key = cid.ID
	if strings.TrimSpace(key) == "" {
		// use document hash as key to avoid duplicates if id is missing
		digest := sha256.Sum256(content)

		key = hex.EncodeToString(digest[0:])
	}

	return key, nil
}

type hasJTI struct {
	JTI string `json:"jti"`
}

func getJWTContentID(jwtStr string) (string, error) {
	parts := strings.Split(unQuote(jwtStr), ".")
	if len(parts) != 3 { // nolint: gomnd
		return "", nil // assume not a jwt
	}

	credBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode base64 JWT data: %w", err)
	}

	cred := &hasJTI{}

	err = json.Unmarshal(credBytes, cred)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JWT data: %w", err)
	}

	if cred.JTI == "" {
		return "", fmt.Errorf("JWT data has no ID")
	}

	return cred.JTI, nil
}

func unQuote(s string) string {
	if len(s) <= 1 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}

	return s
}

// GetAll returns all stored credentials.
func (w *Wallet) GetAll() (map[string]json.RawMessage, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	iter, queryErr := w.store.Query(credentialTag)
	if queryErr != nil {
		return nil, queryErr
	}

	credentials := make(map[string]json.RawMessage)

	for {
		ok, err := iter.Next()
		if err != nil {
			return nil, err
		}

		if !ok {
			break
		}

		k, err := iter.Key()
		if err != nil {
			return nil, err
		}

		v, err := iter.Value()
		if err != nil {
			return nil, err
		}

		credentials[k] = v
	}

	return credentials, nil
}

// Query runs the given presentation definition on the stored credentials.
func (w *Wallet) Query(
	pdBytes []byte,
	jwtVPFormat bool,
	useMultiVPs bool,
) ([]*verifiable.Presentation, *presexch.PresentationSubmission, error) {
	vcContent, err := w.GetAll()
	if err != nil {
		return nil, nil, fmt.Errorf("query credentials: %w", err)
	}

	if len(vcContent) == 0 {
		return nil, nil, fmt.Errorf("no credentials found in wallet")
	}

	credentials, err := parseCredentialContents(vcContent, w.documentLoader)
	if err != nil {
		return nil, nil, err
	}

	var pd presexch.PresentationDefinition

	if err = json.Unmarshal(pdBytes, &pd); err != nil {
		return nil, nil, err
	}

	opts := []presexch.MatchRequirementsOpt{
		presexch.WithSDCredentialOptions(
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(w.documentLoader),
		),
	}

	if jwtVPFormat {
		opts = append(opts, presexch.WithDefaultPresentationFormat(presexch.FormatJWTVP))
	}

	if useMultiVPs {
		vps, presentationSubmission, createErr := pd.CreateVPArray(credentials, w.documentLoader, opts...)
		if createErr != nil {
			if errors.Is(createErr, presexch.ErrNoCredentials) {
				return nil, nil, fmt.Errorf("no matching credentials found")
			}

			return nil, nil, createErr
		}

		return vps, presentationSubmission, nil
	}

	var vp *verifiable.Presentation

	vp, err = pd.CreateVP(credentials, w.documentLoader, opts...)
	if err != nil {
		if errors.Is(err, presexch.ErrNoCredentials) {
			return nil, nil, fmt.Errorf("no matching credentials found")
		}

		return nil, nil, err
	}

	presentationSubmission, ok := vp.CustomFields["presentation_submission"].(*presexch.PresentationSubmission)
	if !ok {
		return nil, nil, fmt.Errorf("missing or invalid presentation_submission")
	}

	return []*verifiable.Presentation{vp}, presentationSubmission, nil
}

func parseCredentialContents(m map[string]json.RawMessage, loader ld.DocumentLoader) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	for _, vcData := range m {
		vc, err := verifiable.ParseCredential(vcData,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader),
		)
		if err != nil {
			return nil, err
		}

		credentials = append(credentials, vc)
	}

	return credentials, nil
}

func (w *Wallet) DIDs() []*DIDInfo {
	return w.dids
}

func (w *Wallet) SignatureType() vcs.SignatureType {
	return w.signatureType
}

func (w *Wallet) Name() string {
	return w.name
}

func (w *Wallet) Version() string {
	return w.version
}

func (w *Wallet) WalletType() string {
	return w.walletType
}

func (w *Wallet) Compliance() string {
	return w.compliance
}

func WithNewDID(method string) Opt {
	return func(opts *options) {
		opts.newDIDs = append(opts.newDIDs, method)
	}
}

func WithKeyType(keyType kmsapi.KeyType) Opt {
	return func(opts *options) {
		opts.keyType = keyType
	}
}

func WithName(name string) Opt {
	return func(opts *options) {
		opts.name = name
	}
}

func WithVersion(version string) Opt {
	return func(opts *options) {
		opts.version = version
	}
}

func WithWalletType(walletType string) Opt {
	return func(opts *options) {
		opts.walletType = walletType
	}
}

func WithCompliance(compliance string) Opt {
	return func(opts *options) {
		opts.compliance = compliance
	}
}
