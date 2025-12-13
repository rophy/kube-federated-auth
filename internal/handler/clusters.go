package handler

import (
	"encoding/json"
	"net/http"

	"github.com/rophy/multi-k8s-auth/internal/config"
)

type ClustersResponse struct {
	Clusters []string `json:"clusters"`
}

type ClustersHandler struct {
	config *config.Config
}

func NewClustersHandler(cfg *config.Config) *ClustersHandler {
	return &ClustersHandler{config: cfg}
}

func (h *ClustersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ClustersResponse{
		Clusters: h.config.ClusterNames(),
	})
}
