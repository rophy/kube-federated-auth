package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rophy/multi-k8s-auth/internal/config"
)

type Claims struct {
	Cluster    string         `json:"cluster"`
	Issuer     string         `json:"iss"`
	Subject    string         `json:"sub"`
	Audience   []string       `json:"aud"`
	Expiry     int64          `json:"exp"`
	IssuedAt   int64          `json:"iat"`
	NotBefore  int64          `json:"nbf,omitempty"`
	Kubernetes map[string]any `json:"kubernetes.io,omitempty"`
}

type VerifierManager struct {
	mu        sync.RWMutex
	verifiers map[string]*oidc.IDTokenVerifier
	config    *config.Config
}

func NewVerifierManager(cfg *config.Config) *VerifierManager {
	return &VerifierManager{
		verifiers: make(map[string]*oidc.IDTokenVerifier),
		config:    cfg,
	}
}

func (m *VerifierManager) Verify(ctx context.Context, clusterName, rawToken string) (*Claims, error) {
	clusterCfg, ok := m.config.Clusters[clusterName]
	if !ok {
		return nil, fmt.Errorf("cluster not found: %s", clusterName)
	}

	verifier, err := m.getOrCreateVerifier(ctx, clusterName, clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	token, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	var rawClaims struct {
		Issuer     string         `json:"iss"`
		Subject    string         `json:"sub"`
		Expiry     int64          `json:"exp"`
		IssuedAt   int64          `json:"iat"`
		NotBefore  int64          `json:"nbf"`
		Kubernetes map[string]any `json:"kubernetes.io"`
	}
	if err := token.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	return &Claims{
		Cluster:    clusterName,
		Issuer:     rawClaims.Issuer,
		Subject:    rawClaims.Subject,
		Audience:   token.Audience,
		Expiry:     rawClaims.Expiry,
		IssuedAt:   rawClaims.IssuedAt,
		NotBefore:  rawClaims.NotBefore,
		Kubernetes: rawClaims.Kubernetes,
	}, nil
}

func (m *VerifierManager) getOrCreateVerifier(ctx context.Context, name string, cfg config.ClusterConfig) (*oidc.IDTokenVerifier, error) {
	m.mu.RLock()
	if v, ok := m.verifiers[name]; ok {
		m.mu.RUnlock()
		return v, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if v, ok := m.verifiers[name]; ok {
		return v, nil
	}

	httpClient, err := m.createHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	m.verifiers[name] = verifier
	return verifier, nil
}

func (m *VerifierManager) createHTTPClient(cfg config.ClusterConfig) (*http.Client, error) {
	var transport http.RoundTripper = http.DefaultTransport

	if cfg.CACert != "" {
		caCert, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}

		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}

	if cfg.TokenPath != "" {
		transport = &tokenRoundTripper{
			transport: transport,
			tokenPath: cfg.TokenPath,
		}
	}

	return &http.Client{Transport: transport}, nil
}

type tokenRoundTripper struct {
	transport http.RoundTripper
	tokenPath string
}

func (t *tokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := os.ReadFile(t.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}

	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+string(token))

	return t.transport.RoundTrip(req)
}
