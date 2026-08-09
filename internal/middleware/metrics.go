package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsMiddleware records HTTP request count and duration.
func MetricsMiddleware(requestsTotal *prometheus.CounterVec, requestDuration *prometheus.HistogramVec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &StatusResponseWriter{ResponseWriter: w}

			next.ServeHTTP(ww, r)

			path := r.Pattern
			if path == "" {
				path = r.URL.Path
			}
			method := r.Method
			status := strconv.Itoa(ww.Status())

			requestsTotal.WithLabelValues(method, path, status).Inc()
			requestDuration.WithLabelValues(method, path).Observe(time.Since(start).Seconds())
		})
	}
}
