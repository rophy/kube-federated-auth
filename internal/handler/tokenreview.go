package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/oidc"
)

type TokenReviewHandler struct {
	verifier  *oidc.VerifierManager
	config    *config.Config
	credStore *credentials.Store
}

func NewTokenReviewHandler(v *oidc.VerifierManager, cfg *config.Config, store *credentials.Store) *TokenReviewHandler {
	return &TokenReviewHandler{
		verifier:  v,
		config:    cfg,
		credStore: store,
	}
}

func (h *TokenReviewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse TokenReview request
	var tr authv1.TokenReview
	if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if tr.Spec.Token == "" {
		h.writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	if h.verifier == nil || h.config == nil {
		h.writeUnauthenticated(w, &tr, "server not configured")
		return
	}

	// Step 1: Detect cluster via JWKS (local, no token leakage)
	cluster, err := h.detectCluster(r.Context(), tr.Spec.Token)
	if err != nil {
		log.Printf("Cluster detection failed: %v", err)
		h.writeUnauthenticated(w, &tr, "token not valid for any configured cluster")
		return
	}

	log.Printf("Detected cluster: %s", cluster)

	// Step 2: Forward TokenReview to detected cluster
	result, err := h.forwardTokenReview(r.Context(), cluster, &tr)
	if err != nil {
		log.Printf("TokenReview forwarding failed for cluster %s: %v", cluster, err)
		h.writeUnauthenticated(w, &tr, fmt.Sprintf("failed to validate token: %v", err))
		return
	}

	// Return the response from the remote cluster
	json.NewEncoder(w).Encode(result)
}

// detectCluster tries to verify the token against all configured clusters using JWKS.
// This is done locally without sending the token anywhere.
// Returns the cluster name that successfully verified the token signature.
func (h *TokenReviewHandler) detectCluster(ctx context.Context, token string) (string, error) {
	for clusterName := range h.config.Clusters {
		_, err := h.verifier.Verify(ctx, clusterName, token)
		if err == nil {
			return clusterName, nil
		}
		// Signature didn't match - try next cluster
		log.Printf("Token not valid for cluster %s: %v", clusterName, err)
	}
	return "", fmt.Errorf("token signature does not match any configured cluster")
}

// forwardTokenReview sends the TokenReview request to the detected cluster's API server.
func (h *TokenReviewHandler) forwardTokenReview(ctx context.Context, clusterName string, tr *authv1.TokenReview) (*authv1.TokenReview, error) {
	clusterCfg, ok := h.config.Clusters[clusterName]
	if !ok {
		return nil, fmt.Errorf("cluster not found: %s", clusterName)
	}

	// Build REST config for the target cluster
	restConfig, err := h.buildRESTConfig(clusterName, clusterCfg)
	if err != nil {
		return nil, fmt.Errorf("building REST config: %w", err)
	}

	// Create Kubernetes client
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	// Forward TokenReview request
	result, err := client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("calling TokenReview API: %w", err)
	}

	// Ensure TypeMeta is set (k8s client doesn't populate this on responses)
	result.APIVersion = "authentication.k8s.io/v1"
	result.Kind = "TokenReview"

	return result, nil
}

// buildRESTConfig creates a REST config for the target cluster
func (h *TokenReviewHandler) buildRESTConfig(clusterName string, clusterCfg config.ClusterConfig) (*rest.Config, error) {
	// For clusters with api_server, use remote credentials
	if clusterCfg.APIServer != "" {
		var bearerToken string
		var caCert []byte

		if h.credStore != nil {
			if creds, ok := h.credStore.Get(clusterName); ok {
				bearerToken = creds.Token
				caCert = creds.CACert
			}
		}

		return &rest.Config{
			Host:        clusterCfg.APIServer,
			BearerToken: bearerToken,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: caCert,
			},
		}, nil
	}

	// For local clusters, try in-cluster config first
	inClusterConfig, err := rest.InClusterConfig()
	if err == nil {
		return inClusterConfig, nil
	}

	// Fallback: use issuer as host (for testing)
	return &rest.Config{
		Host: clusterCfg.Issuer,
	}, nil
}

func (h *TokenReviewHandler) writeUnauthenticated(w http.ResponseWriter, req *authv1.TokenReview, errMsg string) {
	resp := &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.k8s.io/v1",
			Kind:       "TokenReview",
		},
		Status: authv1.TokenReviewStatus{
			Authenticated: false,
			Error:         errMsg,
		},
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *TokenReviewHandler) writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	resp := &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.k8s.io/v1",
			Kind:       "TokenReview",
		},
		Status: authv1.TokenReviewStatus{
			Authenticated: false,
			Error:         msg,
		},
	}
	json.NewEncoder(w).Encode(resp)
}
