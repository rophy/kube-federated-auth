package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/rophy/multi-k8s-auth/internal/config"
	"github.com/rophy/multi-k8s-auth/internal/credentials"
	"github.com/rophy/multi-k8s-auth/internal/oidc"
)

type RegisterRequest struct {
	Cluster     string             `json:"cluster"`
	Credentials RegisterCredentials `json:"credentials"`
}

type RegisterCredentials struct {
	Token  string `json:"token"`
	CACert string `json:"ca_cert"` // Base64-encoded CA certificate
}

type RegisterResponse struct {
	Status    string `json:"status"`
	Cluster   string `json:"cluster"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type RegisterHandler struct {
	verifier *oidc.VerifierManager
	config   *config.Config
	store    *credentials.Store
}

func NewRegisterHandler(v *oidc.VerifierManager, cfg *config.Config, store *credentials.Store) *RegisterHandler {
	return &RegisterHandler{
		verifier: v,
		config:   cfg,
		store:    store,
	}
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Extract Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "unauthorized",
			Message: "Authorization header required",
		})
		return
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "unauthorized",
			Message: "Bearer token required",
		})
		return
	}

	agentToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse request body
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	if req.Cluster == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "invalid_request",
			Message: "cluster is required",
		})
		return
	}

	// Check if cluster exists in config
	if _, ok := h.config.Clusters[req.Cluster]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "cluster_not_found",
			Message: "No configuration found for cluster: " + req.Cluster,
		})
		return
	}

	// Validate agent token against the cluster's OIDC
	claims, err := h.verifier.Verify(r.Context(), req.Cluster, agentToken)
	if err != nil {
		log.Printf("Agent token validation failed for cluster %s: %v", req.Cluster, err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "invalid_token",
			Message: "Agent token validation failed",
		})
		return
	}

	// Check if agent ServiceAccount is authorized
	if !h.config.IsAgentAuthorized(req.Cluster, claims.Subject) {
		log.Printf("Unauthorized agent %s for cluster %s", claims.Subject, req.Cluster)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "unauthorized_agent",
			Message: "ServiceAccount not authorized to register credentials for " + req.Cluster,
		})
		return
	}

	// Decode CA certificate
	caCert, err := credentials.ParseBase64CACert(req.Credentials.CACert)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid CA certificate encoding",
		})
		return
	}

	// Store credentials
	creds := &credentials.Credentials{
		Token:  req.Credentials.Token,
		CACert: caCert,
	}

	if err := h.store.Set(r.Context(), req.Cluster, creds); err != nil {
		log.Printf("Failed to store credentials for cluster %s: %v", req.Cluster, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to store credentials",
		})
		return
	}

	log.Printf("Registered credentials for cluster %s from agent %s", req.Cluster, claims.Subject)

	// Invalidate cached verifier to pick up new credentials
	h.verifier.InvalidateVerifier(req.Cluster)

	json.NewEncoder(w).Encode(RegisterResponse{
		Status:    "accepted",
		Cluster:   req.Cluster,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
	})
}
