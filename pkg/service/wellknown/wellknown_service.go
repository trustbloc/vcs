package wellknown

import (
	"context"
	"errors"
	"fmt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/resterr"
	"net/url"
	"time"
)

type verifierProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Verifier, error)
}

type issuerProfileService interface {
	GetProfile(profileID profileapi.ID) (*profileapi.Issuer, error)
}

type issueCredentialService interface {
	IssueCredential(credential *verifiable.Credential,
		issuerSigningOpts []crypto.SigningOpts,
		profile *profileapi.Issuer) (*verifiable.Credential, error)
}

type ProfileType string

const (
	ProfileTypeIssuer   = ProfileType("issuer")
	ProfileTypeVerifier = ProfileType("verifier")
)

type Config struct {
	VerifierProfileService  verifierProfileService
	IssuerProfileService    issuerProfileService
	IssuerCredentialService issueCredentialService
}

type Service struct {
	verifierProfileService  verifierProfileService
	issuerProfileService    issuerProfileService
	issuerCredentialService issueCredentialService
}

func New(
	config *Config,
) *Service {
	return &Service{
		verifierProfileService:  config.VerifierProfileService,
		issuerProfileService:    config.IssuerProfileService,
		issuerCredentialService: config.IssuerCredentialService,
	}
}

func (s *Service) DidConfig(
	ctx context.Context,
	profileType ProfileType,
	profileID string,
	contextUrl string,
) (*verifiable.Credential, error) {
	var issuer *profileapi.Issuer

	u, err := url.Parse(contextUrl)

	if err != nil {
		return nil, err
	}

	switch profileType {
	case ProfileTypeVerifier:
		s.verifierProfileService.GetProfile(profileID)
	case ProfileTypeIssuer:
		if profile, err := s.issuerProfileService.GetProfile(profileID); err != nil {
			return nil, resterr.NewValidationError(resterr.SystemError, "profileID",
				err)
		} else {
			issuer = profile
		}
	default:
		return nil, resterr.NewValidationError(resterr.InvalidValue, "profileType",
			errors.New("profileType should be verifier or issuer"))
	}

	cred, err := s.issuerCredentialService.IssueCredential(&verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			contextUrl,
		},
		Types: []string{
			"VerifiableCredential",
			"DomainLinkageCredential",
		},
		Issuer: verifiable.Issuer{
			ID: issuer.ID,
		},
		Issued: util.NewTime(time.Now().UTC()),
		Subject: map[string]interface{}{
			"id":     issuer.ID,
			"origin": fmt.Sprintf("%s://%s", u.Scheme, u.Hostname()),
		},
	}, nil, issuer)

	if err != nil {
		return nil, err
	}

	return cred, nil
}
