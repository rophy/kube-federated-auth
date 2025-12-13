package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rophy/multi-k8s-auth/internal/config"
	"github.com/rophy/multi-k8s-auth/internal/handler"
	"github.com/rophy/multi-k8s-auth/internal/oidc"
)

func New(cfg *config.Config) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	verifier := oidc.NewVerifierManager(cfg)

	r.Get("/health", handler.Health)
	r.Get("/clusters", handler.NewClustersHandler(cfg).ServeHTTP)
	r.Post("/validate", handler.NewValidateHandler(verifier).ServeHTTP)

	return r
}
