package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rophy/kube-federated-auth/internal/config"
	"github.com/rophy/kube-federated-auth/internal/credentials"
	"github.com/rophy/kube-federated-auth/internal/handler"
	"github.com/rophy/kube-federated-auth/internal/oidc"
)

// Server holds the HTTP handler and verifier manager
type Server struct {
	Handler  http.Handler
	Verifier *oidc.VerifierManager
}

func New(cfg *config.Config, credStore *credentials.Store, version string) *Server {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	verifier := oidc.NewVerifierManager(cfg, credStore)

	r.Get("/health", handler.NewHealthHandler(version).ServeHTTP)
	r.Get("/clusters", handler.NewClustersHandler(cfg, credStore).ServeHTTP)
	r.Post("/apis/authentication.k8s.io/v1/tokenreviews", handler.NewTokenReviewHandler(verifier, cfg, credStore).ServeHTTP)

	return &Server{
		Handler:  r,
		Verifier: verifier,
	}
}
