package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rophy/kube-federated-auth/internal/oidc"
)

type TokenReviewHandler struct {
	verifier *oidc.VerifierManager
}

func NewTokenReviewHandler(v *oidc.VerifierManager) *TokenReviewHandler {
	return &TokenReviewHandler{verifier: v}
}

func (h *TokenReviewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Extract cluster from Host header
	cluster := extractClusterFromHost(r.Host)
	if cluster == "" {
		h.writeError(w, http.StatusBadRequest, "unable to determine cluster from host header")
		return
	}

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

	// Validate token using OIDC verifier
	if h.verifier == nil {
		h.writeUnauthenticated(w, &tr, "verifier not configured")
		return
	}

	claims, err := h.verifier.Verify(r.Context(), cluster, tr.Spec.Token)
	if err != nil {
		log.Printf("Token validation failed for cluster %s: %v", cluster, err)
		h.writeUnauthenticated(w, &tr, err.Error())
		return
	}

	// Build successful response
	h.writeAuthenticated(w, &tr, claims)
}

// extractClusterFromHost extracts the cluster name from the Host header.
// Expected formats:
//   - api.{cluster}.kube-fed.svc.cluster.local -> cluster
//   - api.{cluster}.kube-fed.svc -> cluster
//   - api.{cluster}.kube-fed -> cluster
//   - api.kube-fed.svc.cluster.local -> "local"
//   - api.kube-fed -> "local"
func extractClusterFromHost(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}

	// Expect format: api.{cluster}.kube-fed... or api.kube-fed...
	if parts[0] != "api" {
		return ""
	}

	// api.kube-fed... -> local cluster
	if parts[1] == "kube-fed" {
		return "local"
	}

	// api.{cluster}.kube-fed... -> named cluster
	if len(parts) >= 3 && parts[2] == "kube-fed" {
		return parts[1]
	}

	return ""
}

func (h *TokenReviewHandler) writeAuthenticated(w http.ResponseWriter, req *authv1.TokenReview, claims *oidc.Claims) {
	// Extract user info from claims
	username := claims.Subject
	groups := extractGroups(claims)
	extra := extractExtra(claims)

	resp := &authv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authentication.k8s.io/v1",
			Kind:       "TokenReview",
		},
		Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User: authv1.UserInfo{
				Username: username,
				UID:      getUID(claims),
				Groups:   groups,
				Extra:    extra,
			},
			Audiences: claims.Audience,
		},
	}

	json.NewEncoder(w).Encode(resp)
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

// extractGroups extracts group information from kubernetes.io claims
func extractGroups(claims *oidc.Claims) []string {
	if claims.Kubernetes == nil {
		return nil
	}

	// Try to get groups from kubernetes.io claims
	if groups, ok := claims.Kubernetes["groups"].([]interface{}); ok {
		result := make([]string, 0, len(groups))
		for _, g := range groups {
			if s, ok := g.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// extractExtra extracts extra fields from kubernetes.io claims
func extractExtra(claims *oidc.Claims) map[string]authv1.ExtraValue {
	if claims.Kubernetes == nil {
		return nil
	}

	extra := make(map[string]authv1.ExtraValue)

	// Extract pod binding info if present
	if pod, ok := claims.Kubernetes["pod"].(map[string]interface{}); ok {
		if name, ok := pod["name"].(string); ok {
			extra["authentication.kubernetes.io/pod-name"] = authv1.ExtraValue{name}
		}
		if uid, ok := pod["uid"].(string); ok {
			extra["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue{uid}
		}
	}

	// Extract serviceaccount info if present
	if sa, ok := claims.Kubernetes["serviceaccount"].(map[string]interface{}); ok {
		if name, ok := sa["name"].(string); ok {
			extra["authentication.kubernetes.io/serviceaccount/name"] = authv1.ExtraValue{name}
		}
		if ns, ok := sa["namespace"].(string); ok {
			extra["authentication.kubernetes.io/serviceaccount/namespace"] = authv1.ExtraValue{ns}
		}
	}

	if len(extra) == 0 {
		return nil
	}

	return extra
}

// getUID extracts the UID from claims
func getUID(claims *oidc.Claims) string {
	if claims.Kubernetes == nil {
		return ""
	}

	if sa, ok := claims.Kubernetes["serviceaccount"].(map[string]interface{}); ok {
		if uid, ok := sa["uid"].(string); ok {
			return uid
		}
	}

	return ""
}
