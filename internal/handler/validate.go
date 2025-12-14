package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/rophy/kube-federated-auth/internal/oidc"
)

type ValidateRequest struct {
	Cluster string `json:"cluster"`
	Token   string `json:"token"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type ValidateHandler struct {
	verifier *oidc.VerifierManager
}

func NewValidateHandler(v *oidc.VerifierManager) *ValidateHandler {
	return &ValidateHandler{verifier: v}
}

func (h *ValidateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
		})
		return
	}

	if req.Cluster == "" || req.Token == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{
			Error:   "invalid_request",
			Message: "cluster and token are required",
		})
		return
	}

	claims, err := h.verifier.Verify(r.Context(), req.Cluster, req.Token)
	if err != nil {
		log.Printf("Validation error for cluster %s: %v", req.Cluster, err)
		code, errResp := mapError(err)
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(errResp)
		return
	}

	json.NewEncoder(w).Encode(claims)
}

func mapError(err error) (int, ErrorResponse) {
	errStr := err.Error()

	if strings.Contains(errStr, "cluster not found") {
		return http.StatusBadRequest, ErrorResponse{
			Error:   "cluster_not_found",
			Message: errStr,
		}
	}

	if strings.Contains(errStr, "token is expired") {
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "token_expired",
			Message: "Token has expired",
		}
	}

	if strings.Contains(errStr, "signature") || strings.Contains(errStr, "verifying token") {
		return http.StatusUnauthorized, ErrorResponse{
			Error:   "invalid_signature",
			Message: "Token signature verification failed",
		}
	}

	if strings.Contains(errStr, "OIDC provider") || strings.Contains(errStr, "discovery") {
		return http.StatusInternalServerError, ErrorResponse{
			Error:   "oidc_discovery_failed",
			Message: "Failed to fetch OIDC discovery document",
		}
	}

	if strings.Contains(errStr, "JWKS") {
		return http.StatusInternalServerError, ErrorResponse{
			Error:   "jwks_fetch_failed",
			Message: "Failed to fetch JWKS",
		}
	}

	return http.StatusUnauthorized, ErrorResponse{
		Error:   "invalid_token",
		Message: errStr,
	}
}
