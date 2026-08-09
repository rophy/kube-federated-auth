package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoverer_NoPanic(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Recoverer(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRecoverer_Panic(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := Recoverer(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestStatusResponseWriter_DefaultStatus(t *testing.T) {
	w := &StatusResponseWriter{ResponseWriter: httptest.NewRecorder()}
	if w.Status() != http.StatusOK {
		t.Errorf("default status = %d, want %d", w.Status(), http.StatusOK)
	}
}

func TestStatusResponseWriter_CapturesStatus(t *testing.T) {
	w := &StatusResponseWriter{ResponseWriter: httptest.NewRecorder()}
	w.WriteHeader(http.StatusNotFound)
	if w.Status() != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Status(), http.StatusNotFound)
	}
}

func TestContextHelpers_CallerIdentity(t *testing.T) {
	ctx := context.Background()
	if v := GetCallerIdentity(ctx); v != "" {
		t.Errorf("expected empty, got %q", v)
	}

	ctx = SetCallerIdentity(ctx, "cluster-a/default/my-app")
	if v := GetCallerIdentity(ctx); v != "cluster-a/default/my-app" {
		t.Errorf("got %q, want %q", v, "cluster-a/default/my-app")
	}
}

func TestContextHelpers_ClientIdentity(t *testing.T) {
	ctx := context.Background()
	if v := GetClientIdentity(ctx); v != "" {
		t.Errorf("expected empty, got %q", v)
	}

	ctx = SetClientIdentity(ctx, "cluster-b/ns/sa")
	if v := GetClientIdentity(ctx); v != "cluster-b/ns/sa" {
		t.Errorf("got %q, want %q", v, "cluster-b/ns/sa")
	}
}

func TestContextHelpers_ErrorMessage(t *testing.T) {
	ctx := context.Background()
	if v := GetErrorMessage(ctx); v != "" {
		t.Errorf("expected empty, got %q", v)
	}

	ctx = SetErrorMessage(ctx, "something went wrong")
	if v := GetErrorMessage(ctx); v != "something went wrong" {
		t.Errorf("got %q, want %q", v, "something went wrong")
	}
}

func TestRequestLogger_200(t *testing.T) {
	logger := slog.Default()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequestLogger_500(t *testing.T) {
	logger := slog.Default()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestRequestLogger_400WithError(t *testing.T) {
	logger := slog.Default()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*r = *r.WithContext(SetErrorMessage(r.Context(), "bad request"))
		w.WriteHeader(http.StatusBadRequest)
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRequestLogger_WithContextIdentities(t *testing.T) {
	logger := slog.Default()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = SetCallerIdentity(ctx, "cluster-a/ns/caller")
		ctx = SetClientIdentity(ctx, "cluster-b/ns/client")
		*r = *r.WithContext(ctx)
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest(http.MethodPost, "/tokenreview", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequestLogger_DefaultStatus(t *testing.T) {
	// When handler doesn't call WriteHeader, status should default to 200
	logger := slog.Default()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	handler := RequestLogger(logger)(inner)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
