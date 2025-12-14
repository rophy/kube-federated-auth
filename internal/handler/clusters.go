package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rophy/multi-k8s-auth/internal/config"
	"github.com/rophy/multi-k8s-auth/internal/credentials"
)

type ClusterInfo struct {
	Name        string       `json:"name"`
	Issuer      string       `json:"issuer"`
	APIServer   string       `json:"api_server,omitempty"`
	TokenStatus *TokenStatus `json:"token_status,omitempty"`
}

type TokenStatus struct {
	ExpiresAt string `json:"expires_at,omitempty"`
	ExpiresIn string `json:"expires_in,omitempty"`
	Status    string `json:"status"` // "valid", "expiring_soon", "expired", "unknown"
}

type ClustersResponse struct {
	Clusters []ClusterInfo `json:"clusters"`
}

type ClustersHandler struct {
	config    *config.Config
	credStore *credentials.Store
}

func NewClustersHandler(cfg *config.Config, credStore *credentials.Store) *ClustersHandler {
	return &ClustersHandler{config: cfg, credStore: credStore}
}

func (h *ClustersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var clusters []ClusterInfo
	for name, cfg := range h.config.Clusters {
		info := ClusterInfo{
			Name:      name,
			Issuer:    cfg.Issuer,
			APIServer: cfg.APIServer,
		}

		// Add token status if we have credentials for this cluster
		if h.credStore != nil {
			if creds, ok := h.credStore.Get(name); ok {
				info.TokenStatus = getTokenStatus(creds)
			}
		}

		clusters = append(clusters, info)
	}

	json.NewEncoder(w).Encode(ClustersResponse{Clusters: clusters})
}

func getTokenStatus(creds *credentials.Credentials) *TokenStatus {
	if creds == nil || creds.Token == "" {
		return &TokenStatus{Status: "unknown"}
	}

	exp, err := extractJWTExpiration(creds.Token)
	if err != nil || exp == 0 {
		return &TokenStatus{Status: "unknown"}
	}

	now := time.Now()
	expiresAt := time.Unix(exp, 0)
	status := &TokenStatus{
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}

	if now.After(expiresAt) {
		status.Status = "expired"
		status.ExpiresIn = "expired"
	} else {
		remaining := expiresAt.Sub(now)
		status.ExpiresIn = remaining.Round(time.Second).String()

		if remaining < 10*time.Minute {
			status.Status = "expiring_soon"
		} else {
			status.Status = "valid"
		}
	}

	return status
}

func extractJWTExpiration(token string) (int64, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, err
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, err
	}

	return claims.Exp, nil
}
