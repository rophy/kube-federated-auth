package credentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rophy/multi-k8s-auth/internal/config"
)

// VerifierInvalidator is an interface for invalidating cached verifiers
type VerifierInvalidator interface {
	InvalidateVerifier(clusterName string)
}

// Renewer handles automatic credential renewal for remote clusters
type Renewer struct {
	config    *config.Config
	credStore *Store
	verifier  VerifierInvalidator
}

// NewRenewer creates a new credential renewer
func NewRenewer(cfg *config.Config, store *Store, verifier VerifierInvalidator) *Renewer {
	return &Renewer{
		config:    cfg,
		credStore: store,
		verifier:  verifier,
	}
}

// Start begins the renewal loops for all remote clusters
func (r *Renewer) Start(ctx context.Context) {
	interval := r.config.GetRenewalInterval()
	for clusterName, clusterCfg := range r.config.Clusters {
		if clusterCfg.IsRemote() {
			go r.renewLoop(ctx, clusterName, clusterCfg, interval)
		}
	}
}

func (r *Renewer) renewLoop(ctx context.Context, cluster string, cfg config.ClusterConfig, interval time.Duration) {
	log.Printf("Starting credential renewal loop for cluster %s (interval: %s)", cluster, interval)

	// Initial renewal
	if err := r.renew(ctx, cluster, cfg); err != nil {
		log.Printf("Initial credential renewal failed for cluster %s: %v", cluster, err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.renew(ctx, cluster, cfg); err != nil {
				log.Printf("Credential renewal failed for cluster %s: %v", cluster, err)
			}
		case <-ctx.Done():
			log.Printf("Stopping credential renewal loop for cluster %s", cluster)
			return
		}
	}
}

func (r *Renewer) renew(ctx context.Context, cluster string, cfg config.ClusterConfig) error {
	log.Printf("Renewing credentials for cluster %s", cluster)

	// Get current credentials (bootstrap or previously renewed)
	creds, ok := r.credStore.Get(cluster)
	if !ok {
		// Try to load bootstrap credentials from files
		if cfg.TokenPath != "" && cfg.CACert != "" {
			if err := r.credStore.LoadFromFiles(cluster, cfg.TokenPath, cfg.CACert); err != nil {
				return fmt.Errorf("loading bootstrap credentials: %w", err)
			}
			creds, _ = r.credStore.Get(cluster)
		} else {
			return fmt.Errorf("no credentials available for cluster %s", cluster)
		}
	}

	// Extract namespace and service account from current token
	namespace, serviceAccount, err := parseServiceAccountFromToken(creds.Token)
	if err != nil {
		return fmt.Errorf("parsing token subject: %w", err)
	}

	// Create K8s client for remote cluster
	client, err := r.createClient(cfg, creds)
	if err != nil {
		return fmt.Errorf("creating k8s client: %w", err)
	}

	// Call TokenRequest API
	tokenDuration := r.config.GetRenewalTokenDuration()
	expirationSeconds := int64(tokenDuration.Seconds())
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	token, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx,
		serviceAccount,
		tokenRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("requesting token: %w", err)
	}

	// Store new credentials (CA cert doesn't change)
	newCreds := &Credentials{
		Token:  token.Status.Token,
		CACert: creds.CACert,
	}

	if err := r.credStore.Set(ctx, cluster, newCreds); err != nil {
		return fmt.Errorf("storing credentials: %w", err)
	}

	// Invalidate cached verifier to pick up new credentials
	if r.verifier != nil {
		r.verifier.InvalidateVerifier(cluster)
	}

	log.Printf("Successfully renewed credentials for cluster %s (expires: %s)",
		cluster, token.Status.ExpirationTimestamp.Format(time.RFC3339))

	return nil
}

// parseServiceAccountFromToken extracts namespace and service account name from JWT token
// The subject claim format is: system:serviceaccount:<namespace>:<name>
func parseServiceAccountFromToken(token string) (namespace, serviceAccount string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Parse: system:serviceaccount:<namespace>:<name>
	subParts := strings.Split(claims.Subject, ":")
	if len(subParts) != 4 || subParts[0] != "system" || subParts[1] != "serviceaccount" {
		return "", "", fmt.Errorf("unexpected subject format: %s", claims.Subject)
	}

	return subParts[2], subParts[3], nil
}

func (r *Renewer) createClient(cfg config.ClusterConfig, creds *Credentials) (*kubernetes.Clientset, error) {
	// Load CA cert
	var caCert []byte
	if creds != nil && len(creds.CACert) > 0 {
		caCert = creds.CACert
	} else if cfg.CACert != "" {
		var err error
		caCert, err = os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
	}

	// Build TLS config
	tlsConfig := &tls.Config{}
	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Get token
	var token string
	if creds != nil && creds.Token != "" {
		token = creds.Token
	} else if cfg.TokenPath != "" {
		tokenBytes, err := os.ReadFile(cfg.TokenPath)
		if err != nil {
			return nil, fmt.Errorf("reading token: %w", err)
		}
		token = string(tokenBytes)
	}

	// Create REST config
	restConfig := &rest.Config{
		Host:        cfg.APIServer,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caCert,
		},
	}

	return kubernetes.NewForConfig(restConfig)
}
