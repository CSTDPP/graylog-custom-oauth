// Package observability provides Prometheus metrics and health check endpoints.
package observability

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metrics exposed by the auth proxy.
type Metrics struct {
	RequestsTotal        *prometheus.CounterVec
	RequestDuration      *prometheus.HistogramVec
	AuthOperationsTotal  *prometheus.CounterVec
	SSEConnectionsActive prometheus.Gauge
	GraylogAPITotal      *prometheus.CounterVec
}

// NewMetrics creates and registers all Prometheus metrics with the given
// registerer. The caller typically passes prometheus.DefaultRegisterer or a
// custom registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_proxy_requests_total",
			Help: "Total number of HTTP requests handled by the proxy.",
		}, []string{"method", "path_pattern", "status"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "auth_proxy_request_duration_seconds",
			Help:    "Histogram of request latencies in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path_pattern"}),

		AuthOperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_proxy_auth_operations_total",
			Help: "Total number of authentication operations.",
		}, []string{"operation", "result"}),

		SSEConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_proxy_sse_connections_active",
			Help: "Number of currently active SSE/MCP streaming connections.",
		}),

		GraylogAPITotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_proxy_graylog_api_total",
			Help: "Total number of Graylog API calls made by the proxy.",
		}, []string{"operation", "status"}),
	}

	reg.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.AuthOperationsTotal,
		m.SSEConnectionsActive,
		m.GraylogAPITotal,
	)

	return m
}

// HealthzHandler returns a handler that always responds with 200 and a JSON
// body indicating the service is alive.
func HealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]string{"status": "ok"}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck,gosec // best-effort health response
	}
}

// HealthChecker is implemented by types that can report backend health.
type HealthChecker interface {
	Healthy(ctx context.Context) error
}

// ReadyzHandler returns a handler that checks whether the Graylog backend is
// reachable. It responds with 200 on success or 503 when the backend is
// unavailable.
func ReadyzHandler(graylogClient HealthChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := graylogClient.Healthy(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			resp := map[string]string{"status": "unavailable", "error": err.Error()}
			json.NewEncoder(w).Encode(resp) //nolint:errcheck,gosec // best-effort health response
			return
		}

		w.WriteHeader(http.StatusOK)
		resp := map[string]string{"status": "ok"}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck,gosec // best-effort health response
	}
}
