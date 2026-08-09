package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// StatusResponseWriter wraps http.ResponseWriter to capture the status code.
type StatusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *StatusResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

type contextKey int

const (
	callerIdentityKey contextKey = iota
	clientIdentityKey
	errorMessageKey
	cacheStatusKey
	clusterNameKey
)

// SetCallerIdentity stores the caller identity in the request context.
func SetCallerIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, callerIdentityKey, identity)
}

// GetCallerIdentity retrieves the caller identity from context.
func GetCallerIdentity(ctx context.Context) string {
	if v, ok := ctx.Value(callerIdentityKey).(string); ok {
		return v
	}
	return ""
}

// SetClientIdentity stores the client (payload token) identity in the request context.
func SetClientIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, clientIdentityKey, identity)
}

// GetClientIdentity retrieves the client identity from context.
func GetClientIdentity(ctx context.Context) string {
	if v, ok := ctx.Value(clientIdentityKey).(string); ok {
		return v
	}
	return ""
}

// SetClusterName stores the detected cluster name in the request context.
func SetClusterName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, clusterNameKey, name)
}

// GetClusterName retrieves the detected cluster name from context.
func GetClusterName(ctx context.Context) string {
	if v, ok := ctx.Value(clusterNameKey).(string); ok {
		return v
	}
	return ""
}

// SetCacheStatus stores the cache status (hit/miss) in the request context.
func SetCacheStatus(ctx context.Context, status string) context.Context {
	return context.WithValue(ctx, cacheStatusKey, status)
}

// GetCacheStatus retrieves the cache status from context.
func GetCacheStatus(ctx context.Context) string {
	if v, ok := ctx.Value(cacheStatusKey).(string); ok {
		return v
	}
	return ""
}

// SetErrorMessage stores an error message in the request context for logging.
func SetErrorMessage(ctx context.Context, msg string) context.Context {
	return context.WithValue(ctx, errorMessageKey, msg)
}

// GetErrorMessage retrieves the error message from context.
func GetErrorMessage(ctx context.Context) string {
	if v, ok := ctx.Value(errorMessageKey).(string); ok {
		return v
	}
	return ""
}

// RequestLogger returns an slog-based request logging middleware.
// It logs one line per request with method, path, status, duration,
// and optionally caller identity and cluster name from context.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &StatusResponseWriter{ResponseWriter: w}

			next.ServeHTTP(ww, r)

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.String("duration", time.Since(start).Round(time.Microsecond).String()),
			}

			if caller := GetCallerIdentity(r.Context()); caller != "" {
				attrs = append(attrs, slog.String("caller", caller))
			}
			if client := GetClientIdentity(r.Context()); client != "" {
				attrs = append(attrs, slog.String("client", client))
			}
			if cs := GetCacheStatus(r.Context()); cs != "" {
				attrs = append(attrs, slog.String("cache", cs))
			}
			errMsg := GetErrorMessage(r.Context())
			if errMsg != "" {
				attrs = append(attrs, slog.String("error", errMsg))
			}

			level := slog.LevelInfo
			if ww.Status() >= 500 {
				level = slog.LevelError
			} else if ww.Status() >= 400 || errMsg != "" {
				level = slog.LevelWarn
			}

			logger.LogAttrs(r.Context(), level, "http request", attrs...)
		})
	}
}
