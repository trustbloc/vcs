package stress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/greenpau/go-calculator"
	"github.com/trustbloc/logutil-go/pkg/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/trustbloc/vcs/component/wallet-cli/pkg/walletrunner/vcprovider"
	"github.com/trustbloc/vcs/test/bdd/pkg/bddutil"
)

var logger = log.New("stress")

type Run struct {
	networkLatency    []time.Duration
	stressTestResults map[string][3]time.Duration // metric -> [avg, max, min]
	cfg               *Config
}

type Config struct {
	TLSConfig            *tls.Config            `json:"-"`
	ApiURL               string                 `json:"api_url"`
	TokenClientID        string                 `json:"token_client_id"`
	TokenClientSecret    string                 `json:"token_client_secret"`
	UserCount            int                    `json:"user_count"`
	ConcurrentRequests   int                    `json:"concurrent_requests"`
	IssuerProfileID      string                 `json:"issuer_profile_id"`
	VerifierProfileID    string                 `json:"verifier_profile_id"`
	CredentialTemplateID string                 `json:"credential_template_id"`
	CredentialType       string                 `json:"credential_type"`
	ClaimData            map[string]interface{} `json:"claim_data"`
	DisableRevokeTest    bool                   `json:"disable_revoke_test"`
	Detailed             bool                   `json:"detailed"`
}

func NewStressRun(
	cfg *Config,
) *Run {
	return &Run{
		cfg:               cfg,
		stressTestResults: map[string][3]time.Duration{},
	}
}

func (r *Run) getNetworkLatency() error {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: r.cfg.TLSConfig,
		},
	}

	for i := 0; i < 5; i++ {
		st := time.Now()
		_, err := httpClient.Get(r.cfg.ApiURL)
		if err != nil {
			return err
		}
		r.networkLatency = append(r.networkLatency, time.Since(st))
	}

	return nil
}

func (r *Run) Run(ctx context.Context) (*Result, error) {
	vcsAPIURL := r.cfg.ApiURL
	if vcsAPIURL == "" {
		return nil, fmt.Errorf("api url is empty")
	}

	c := clientcredentials.Config{
		TokenURL:     vcsAPIURL + "/cognito/oauth2/token",
		ClientID:     r.cfg.TokenClientID,     // os.Getenv("TOKEN_CLIENT_ID")
		ClientSecret: r.cfg.TokenClientSecret, //os.Getenv("TOKEN_CLIENT_SECRET"),
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: r.cfg.TLSConfig,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, tokenErr := c.Token(ctx)
	if tokenErr != nil {
		return nil, fmt.Errorf("failed to get token: %w", tokenErr)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token")
	}

	if err := r.getNetworkLatency(); err != nil {
		return nil, err
	}

	workerPool := bddutil.NewWorkerPool(r.cfg.ConcurrentRequests, logger)

	workerPool.Start()

	st := time.Now()
	for i := 0; i < r.cfg.UserCount; i++ {
		testCase, err := NewTestCase(
			WithVCProviderOption(func(c *vcprovider.Config) {
				c.DidKeyType = "ED25519"
				c.DidMethod = "ion"
				c.InsecureTls = true
				c.KeepWalletOpen = true
			}),
			WithVCSAPIURL(vcsAPIURL),
			WithIssuerProfileID(r.cfg.IssuerProfileID),
			WithVerifierProfileID(r.cfg.VerifierProfileID),
			WithCredentialTemplateID(r.cfg.CredentialTemplateID),
			WithHTTPClient(httpClient),
			WithCredentialType(r.cfg.CredentialType),
			WithClaimData(r.cfg.ClaimData),
			WithToken(idToken),
			WithDisableRevokeTestCase(r.cfg.DisableRevokeTest),
		)
		if err != nil {
			return nil, fmt.Errorf("create test case: %w", err)
		}

		workerPool.Submit(testCase)
	}

	workerPool.Stop()

	perfData := map[string][]time.Duration{}
	perCredential := map[string]*PerCredentialData{}

	var errors []error
	for _, resp := range workerPool.Responses() {
		perCredential[resp.CredentialID] = &PerCredentialData{}

		if resp.Err != nil {
			perCredential[resp.CredentialID].Error = resp.Err.Error()
			errors = append(errors, resp.Err)
			continue
		}

		perfInfo, ok := resp.Resp.(stressTestPerfInfo)
		if !ok {
			return nil, fmt.Errorf("invalid stressTestPerfInfo response")
		}

		perCredential[resp.CredentialID].Metrics = map[string]string{}
		for k, v := range perfInfo {
			perCredential[resp.CredentialID].Metrics[k] = v.String()
			perfData[k] = append(perfData[k], v)
		}
	}

	if len(r.networkLatency) > 0 {
		perfData["__network_latency"] = r.networkLatency
	}

	for k, v := range perfData {
		data := make([]int64, len(v))

		for i, d := range v {
			data[i] = d.Milliseconds()
		}

		calc := calculator.NewInt64(data)

		r.stressTestResults[k] = [3]time.Duration{
			time.Duration(calc.Mean().Register.Mean) * time.Millisecond,
			time.Duration(calc.Max().Register.MaxValue) * time.Millisecond,
			time.Duration(calc.Min().Register.MinValue) * time.Millisecond,
		}
	}

	var metrics []*Metric
	for k, v := range r.stressTestResults {
		metrics = append(metrics, &Metric{
			Name: k,
			Avg:  v[0],
			Max:  v[1],
			Min:  v[2],
		})
	}

	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Name < metrics[j].Name
	})

	return &Result{
		UserCount:          r.cfg.UserCount,
		ConcurrentRequests: r.cfg.ConcurrentRequests,
		Metrics:            metrics,
		TotalDuration:      time.Since(st),
		Errors:             errors,
		PerCredentialData:  perCredential,
	}, nil
}
