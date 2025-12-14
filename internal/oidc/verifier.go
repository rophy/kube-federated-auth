package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
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
	credStore *credentials.Store
}

func NewVerifierManager(cfg *config.Config, credStore *credentials.Store) *VerifierManager {
	return &VerifierManager{
		verifiers: make(map[string]*oidc.IDTokenVerifier),
		config:    cfg,
		credStore: credStore,
	}
}

// InvalidateVerifier removes a cached verifier, forcing recreation with new credentials
func (m *VerifierManager) InvalidateVerifier(clusterName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.verifiers, clusterName)
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

// oidcDiscovery represents the OIDC discovery document
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
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

	httpClient, err := m.createHTTPClient(name, cfg)
	if err != nil {
		return nil, err
	}

	// For remote clusters, the discovery URL (api_server) differs from the issuer
	// We need to manually fetch discovery from api_server but validate tokens with the actual issuer
	discoveryURL := cfg.DiscoveryURL()

	// Fetch OIDC discovery document from the discovery URL
	discovery, err := m.fetchDiscovery(ctx, httpClient, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery from %s: %w", discoveryURL, err)
	}

	// Create a remote key set that fetches JWKS from the discovery URL's JWKS endpoint
	// The JWKS URL from discovery might use the issuer's hostname, so we may need to rewrite it
	jwksURL := discovery.JWKSURL
	if cfg.APIServer != "" {
		// Rewrite JWKS URL to use the API server instead of the internal issuer hostname
		jwksURL = rewriteJWKSURL(discovery.JWKSURL, cfg.APIServer)
	}

	ctx = oidc.ClientContext(ctx, httpClient)
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)

	// Create verifier with the actual issuer from the token (not the discovery URL)
	verifier := oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{
		SkipClientIDCheck: true,
	})

	m.verifiers[name] = verifier
	return verifier, nil
}

// fetchDiscovery fetches the OIDC discovery document from the given URL
func (m *VerifierManager) fetchDiscovery(ctx context.Context, client *http.Client, baseURL string) (*oidcDiscovery, error) {
	wellKnownURL := strings.TrimSuffix(baseURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery returned status %d: %s", resp.StatusCode, string(body))
	}

	var discovery oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("decoding discovery: %w", err)
	}

	return &discovery, nil
}

// rewriteJWKSURL rewrites the JWKS URL to use the API server host instead of the internal issuer host
func rewriteJWKSURL(jwksURL, apiServer string) string {
	// The JWKS URL from k8s discovery typically looks like:
	// https://kubernetes.default.svc.cluster.local/openid/v1/jwks
	// We need to rewrite it to use the API server:
	// https://<api-server>/openid/v1/jwks

	// Find the path part after the host
	const pathPrefix = "/openid/v1/jwks"
	if strings.Contains(jwksURL, pathPrefix) {
		return strings.TrimSuffix(apiServer, "/") + pathPrefix
	}

	// Fallback: just use the original URL
	return jwksURL
}

func (m *VerifierManager) createHTTPClient(clusterName string, cfg config.ClusterConfig) (*http.Client, error) {
	var transport http.RoundTripper = http.DefaultTransport

	// Check for dynamic credentials first
	var caCert []byte
	var token string

	if m.credStore != nil {
		if creds, ok := m.credStore.Get(clusterName); ok {
			caCert = creds.CACert
			token = creds.Token
		}
	}

	// Fall back to file-based credentials if no dynamic credentials
	if caCert == nil && cfg.CACert != "" {
		var err error
		caCert, err = os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
	}

	if caCert != nil {
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

	// Use dynamic token if available, otherwise use token file
	if token != "" {
		transport = &staticTokenRoundTripper{
			transport: transport,
			token:     token,
		}
	} else if cfg.TokenPath != "" {
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

type staticTokenRoundTripper struct {
	transport http.RoundTripper
	token     string
}

func (t *staticTokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}
