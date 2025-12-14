package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rophy/multi-k8s-auth/internal/config"
	"github.com/rophy/multi-k8s-auth/internal/credentials"
	"github.com/rophy/multi-k8s-auth/internal/handler"
	"github.com/rophy/multi-k8s-auth/internal/oidc"
)

// Server holds the HTTP handler and verifier manager
type Server struct {
	Handler  http.Handler
	Verifier *oidc.VerifierManager
}

func New(cfg *config.Config, credStore *credentials.Store) *Server {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	verifier := oidc.NewVerifierManager(cfg, credStore)

	r.Get("/health", handler.Health)
	r.Get("/clusters", handler.NewClustersHandler(cfg, credStore).ServeHTTP)
	r.Post("/validate", handler.NewValidateHandler(verifier).ServeHTTP)

	return &Server{
		Handler:  r,
		Verifier: verifier,
	}
}
